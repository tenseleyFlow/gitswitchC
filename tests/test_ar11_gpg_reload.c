/* AR-11 M20: changed gpg-agent.conf bytes must be applied to a persistent
 * agent before an isolated identity is published.  These tests use the
 * public home/switch flows and the command-runner seam: no real keyring or
 * operator agent is touched. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif

#include "test.h"
#include "error.h"
#include "gitswitch.h"
#include "gpg_manager.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define M20_PRIMARY_FPR "0123456789ABCDEF0123456789ABCDEF01234567"
#define M20_SECRET_LISTING                                                   \
    "sec:-:4096:1:FEEDFACE01234567:1700000000:::-:::scESC:::+:::23::0:\n" \
    "fpr:::::::::" M20_PRIMARY_FPR ":\n"

static const char m20_config_a[] =
    "default-cache-ttl 17\n"
    "pinentry-program /nonexistent/gitswitch-ar11-pinentry\n";
static const char m20_config_b[] =
    "default-cache-ttl 29\n"
    "pinentry-program /nonexistent/gitswitch-ar11-pinentry\n";
static const char m20_live_config_a[] =
    "s2k-count 65536\n"
    "pinentry-program /nonexistent/gitswitch-ar11-pinentry\n";
static const char m20_live_config_b[] =
    "s2k-count 1048576\n"
    "pinentry-program /nonexistent/gitswitch-ar11-pinentry\n";

typedef struct {
    bool present;
    char *value;
} m20_saved_env_t;

typedef struct {
    char root[MAX_PATH_LEN];
    char tools[MAX_PATH_LEN];
    char gpgconf[MAX_PATH_LEN];
    char gpg_connect_agent[MAX_PATH_LEN];
    char base[MAX_PATH_LEN];
    char home[MAX_PATH_LEN];
    char current[MAX_PATH_LEN];
    char source_home[MAX_PATH_LEN];
    char source_config[MAX_PATH_LEN];
    char installed_config[MAX_PATH_LEN];
    char reload_state[MAX_PATH_LEN];
    account_t account;
} m20_fixture_t;

static char g_self_executable[MAX_PATH_LEN];
static char g_expected_home[MAX_PATH_LEN];
static const char *g_expected_reload_config;
static int g_reload_calls;
static int g_reload_protocol_errors;
static int g_gpg_listing_calls;
static int g_config_commits;
static bool g_fail_reload;
static int g_live_reload_calls;
static int g_sync_file_calls;
static int g_sync_directory_calls;
static int g_fail_file_sync_at;
static int g_fail_directory_sync_at;
typedef enum {
    M20_RELOAD_MUTATION_NONE = 0,
    M20_RELOAD_MUTATION_EXACT_CTIME,
    M20_RELOAD_MUTATION_DIFFERENT_BYTES
} m20_reload_mutation_t;
static m20_reload_mutation_t g_reload_mutation;

static m20_saved_env_t m20_save_env(const char *name) {
    const char *value = getenv(name);
    m20_saved_env_t saved = {
        .present = value != NULL,
        .value = value ? strdup(value) : NULL
    };

    return saved;
}

static int m20_restore_env(const char *name, m20_saved_env_t *saved) {
    int rc;

    if (!name || !saved || (saved->present && !saved->value)) {
        errno = EINVAL;
        return -1;
    }
    rc = saved->present ? setenv(name, saved->value, 1) : unsetenv(name);
    free(saved->value);
    saved->value = NULL;
    saved->present = false;
    return rc;
}

static const char *m20_extra_env(const run_opts_t *opts,
                                 const char *prefix) {
    size_t prefix_len;

    if (!opts || !opts->extra_env || !prefix) return NULL;
    prefix_len = strlen(prefix);
    for (size_t i = 0; opts->extra_env[i]; i++) {
        if (strncmp(opts->extra_env[i], prefix, prefix_len) == 0) {
            return opts->extra_env[i] + prefix_len;
        }
    }
    return NULL;
}

static bool m20_unsets_env(const run_opts_t *opts, const char *name) {
    if (!opts || !opts->unset_env || !name) return false;
    for (size_t i = 0; opts->unset_env[i]; i++) {
        if (strcmp(opts->unset_env[i], name) == 0) return true;
    }
    return false;
}

static bool m20_argv_has(const char *const argv[], const char *value) {
    if (!argv || !value) return false;
    for (size_t i = 0; argv[i]; i++) {
        if (strcmp(argv[i], value) == 0) return true;
    }
    return false;
}

static int m20_read_config_at(int home_fd, char *output, size_t output_size) {
    size_t used = 0;
    int fd;

    if (home_fd < 0 || !output || output_size < 2) return -1;
    output[0] = '\0';
    fd = openat(home_fd, "gpg-agent.conf",
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return -1;
    while (used + 1U < output_size) {
        ssize_t count = read(fd, output + used, output_size - used - 1U);

        if (count > 0) {
            used += (size_t)count;
        } else if (count == 0) {
            break;
        } else if (errno != EINTR) {
            close(fd);
            return -1;
        }
    }
    output[used] = '\0';
    if (close(fd) != 0) return -1;
    return 0;
}

static bool m20_reload_shape_is_exact(const char *const argv[]) {
    return argv && argv[0] && argv[1] && argv[2] && !argv[3] &&
           argv[0][0] == '/' &&
           ts_command_is(argv[0], "gpgconf") &&
           strcmp(argv[1], "--reload") == 0 &&
           strcmp(argv[2], "gpg-agent") == 0;
}

static bool m20_same_ctime(const struct stat *left,
                           const struct stat *right) {
#ifdef __APPLE__
    return left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}

static int m20_mutate_config_during_reload(m20_reload_mutation_t mutation) {
    char path[MAX_PATH_LEN];
    struct stat before;
    struct stat after;
    struct timespec times[2];
    unsigned char byte;
    int fd;

    if (mutation == M20_RELOAD_MUTATION_NONE ||
        safe_snprintf(path, sizeof(path), "%s/gpg-agent.conf",
                      g_expected_home) != 0) {
        return -1;
    }
    fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0 || fstat(fd, &before) != 0 ||
        pread(fd, &byte, 1, 0) != 1) {
        if (fd >= 0) close(fd);
        return -1;
    }
#ifdef __APPLE__
    times[0] = before.st_atimespec;
    times[1] = before.st_mtimespec;
#else
    times[0] = before.st_atim;
    times[1] = before.st_mtim;
#endif
    if (mutation == M20_RELOAD_MUTATION_DIFFERENT_BYTES) byte ^= 1U;
    if (pwrite(fd, &byte, 1, 0) != 1 ||
        fchmod(fd, 0400) != 0 || fchmod(fd, 0600) != 0 ||
        futimens(fd, times) != 0 || fsync(fd) != 0) {
        close(fd);
        return -1;
    }
    if (close(fd) != 0) return -1;
    if (stat(path, &after) != 0 || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_size != after.st_size ||
        !S_ISREG(after.st_mode) || (after.st_mode & 0777) != 0600 ||
        m20_same_ctime(&before, &after)) {
        return -1;
    }
    return 0;
}

static int m20_runner(const char *const argv[], const run_opts_t *opts,
                      run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
        result->exit_code = 0;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';
    if (argv && argv[0] &&
        (ts_command_is(argv[0], "gpg") ||
         ts_command_is(argv[0], "gpg2") ||
         ts_command_is(argv[0], "gpgconf"))) {
        CHECK(m20_unsets_env(opts, "GPG_AGENT_INFO"));
    }

    if (argv && argv[0] && ts_command_is(argv[0], "gpgconf")) {
        char installed[512];
        struct stat expected;
        struct stat pinned;
        const char *gnupg_home = m20_extra_env(opts, "GNUPGHOME=");

        g_reload_calls++;
        if (!m20_reload_shape_is_exact(argv) || !opts ||
            !opts->use_cwd_fd || opts->cwd_fd < 0 ||
            !gnupg_home || strcmp(gnupg_home, ".") != 0 ||
            stat(g_expected_home, &expected) != 0 ||
            fstat(opts->cwd_fd, &pinned) != 0 ||
            expected.st_dev != pinned.st_dev ||
            expected.st_ino != pinned.st_ino ||
            m20_read_config_at(opts->cwd_fd, installed,
                               sizeof(installed)) != 0 ||
            !g_expected_reload_config ||
            strcmp(installed, g_expected_reload_config) != 0) {
            g_reload_protocol_errors++;
            if (result) result->exit_code = 8;
            return -1;
        }
        if (g_reload_mutation != M20_RELOAD_MUTATION_NONE) {
            m20_reload_mutation_t mutation = g_reload_mutation;
            g_reload_mutation = M20_RELOAD_MUTATION_NONE;
            if (m20_mutate_config_during_reload(mutation) != 0) {
                g_reload_protocol_errors++;
                if (result) result->exit_code = 8;
                return -1;
            }
        }
        if (g_fail_reload) {
            if (result) result->exit_code = 9;
            return -1;
        }
        return 0;
    }

    if (argv && argv[0] &&
        (ts_command_is(argv[0], "gpg") ||
         ts_command_is(argv[0], "gpg2")) &&
        m20_argv_has(argv, "--list-secret-keys")) {
        g_gpg_listing_calls++;
        if (opts && opts->out && opts->out_size > sizeof(M20_SECRET_LISTING)) {
            memcpy(opts->out, M20_SECRET_LISTING,
                   sizeof(M20_SECRET_LISTING));
            if (result) result->out_len = sizeof(M20_SECRET_LISTING) - 1U;
            return 0;
        }
        if (result) result->exit_code = 7;
        return -1;
    }

    return 0;
}

static int m20_real_recording_runner(const char *const argv[],
                                     const run_opts_t *opts,
                                     run_result_t *result) {
    if (m20_reload_shape_is_exact(argv)) g_live_reload_calls++;
    return run_argv_real(argv, opts, result);
}

static int m20_query_agent_number(const char *home, const char *query,
                                  unsigned long long *value) {
    const char *env[] = {"GNUPGHOME=.", NULL};
    char executable[MAX_PATH_LEN];
    char output[512];
    const char *argv[4];
    run_opts_t opts;
    run_result_t result;
    char *line;
    char *end;
    int home_fd;
    int rc;

    if (!home || !query || !value ||
        find_command_path("gpg-connect-agent", executable,
                          sizeof(executable)) != 0) {
        return -1;
    }
    home_fd = open(home, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (home_fd < 0) return -1;
    argv[0] = executable;
    argv[1] = query;
    argv[2] = "/bye";
    argv[3] = NULL;
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.merge_stderr = true;
    opts.extra_env = env;
    opts.cwd_fd = home_fd;
    opts.use_cwd_fd = true;
    rc = run_argv(argv, &opts, &result);
    if (close(home_fd) != 0 || rc != 0 || !result.spawned ||
        result.exit_code != 0 || result.term_signal != 0 ||
        result.out_truncated) {
        return -1;
    }
    line = strstr(output, "D ");
    if (!line) return -1;
    errno = 0;
    *value = strtoull(line + 2, &end, 10);
    if (errno != 0 || end == line + 2 ||
        (*end != '\n' && *end != '\r' && *end != '\0')) {
        return -1;
    }
    return 0;
}

static int m20_count_config_commit(int home_fd, const char *temp_name) {
    struct stat st;

    if (home_fd < 0 || !temp_name || !*temp_name ||
        fstatat(home_fd, temp_name, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(st.st_mode)) {
        return -1;
    }
    g_config_commits++;
    return 0;
}

static int m20_selective_sync(int fd, bool directory) {
    int call;

    if (directory) {
        call = ++g_sync_directory_calls;
        if (g_fail_directory_sync_at > 0 &&
            call == g_fail_directory_sync_at) {
            errno = EIO;
            return -1;
        }
    } else {
        call = ++g_sync_file_calls;
        if (g_fail_file_sync_at > 0 && call == g_fail_file_sync_at) {
            errno = EIO;
            return -1;
        }
    }
    return fsync(fd);
}

static void m20_reset_sync_faults(int fail_file_at, int fail_directory_at) {
    g_sync_file_calls = 0;
    g_sync_directory_calls = 0;
    g_fail_file_sync_at = fail_file_at;
    g_fail_directory_sync_at = fail_directory_at;
}

static void m20_reset_observation(const m20_fixture_t *fixture,
                                  const char *expected_config,
                                  bool fail_reload) {
    g_expected_home[0] = '\0';
    if (fixture) {
        (void)safe_strncpy(g_expected_home, fixture->home,
                           sizeof(g_expected_home));
    }
    g_expected_reload_config = expected_config;
    g_reload_calls = 0;
    g_reload_protocol_errors = 0;
    g_gpg_listing_calls = 0;
    g_fail_reload = fail_reload;
    g_reload_mutation = M20_RELOAD_MUTATION_NONE;
}

static void m20_remove_private_tools(m20_fixture_t *fixture) {
    if (!fixture || fixture->tools[0] == '\0') return;
    ts_rm_rf(fixture->tools);
    fixture->tools[0] = '\0';
    fixture->gpgconf[0] = '\0';
    fixture->gpg_connect_agent[0] = '\0';
}

static int m20_create_private_tool_copies(
    m20_fixture_t *fixture, const char *gpgconf_source,
    const char *gpg_connect_agent_source) {
    const char *leaf;
    size_t parent_len;

    if (!fixture || !gpgconf_source || !gpg_connect_agent_source ||
        g_self_executable[0] != '/') {
        errno = EINVAL;
        return -1;
    }
    leaf = strrchr(g_self_executable, '/');
    if (!leaf || leaf == g_self_executable) return -1;
    parent_len = (size_t)(leaf - g_self_executable);
    if (parent_len + sizeof("/.gitswitch-ar11-reload-tools.XXXXXX") >
            sizeof(fixture->tools) ||
        snprintf(fixture->tools, sizeof(fixture->tools),
                 "%.*s/.gitswitch-ar11-reload-tools.XXXXXX",
                 (int)parent_len, g_self_executable) < 0 ||
        !ts_mkdtemp(fixture->tools) ||
        chmod(fixture->tools, 0700) != 0 ||
        safe_snprintf(fixture->gpgconf, sizeof(fixture->gpgconf),
                      "%s/gpgconf", fixture->tools) != 0 ||
        safe_snprintf(fixture->gpg_connect_agent,
                      sizeof(fixture->gpg_connect_agent),
                      "%s/gpg-connect-agent", fixture->tools) != 0 ||
        copy_file(gpgconf_source, fixture->gpgconf) != 0 ||
        chmod(fixture->gpgconf, 0700) != 0 ||
        copy_file(gpg_connect_agent_source,
                  fixture->gpg_connect_agent) != 0 ||
        chmod(fixture->gpg_connect_agent, 0700) != 0) {
        int saved_errno = errno ? errno : EIO;

        m20_remove_private_tools(fixture);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int m20_use_private_tools_path(const m20_fixture_t *fixture,
                                      bool retain_existing) {
    const char *path = getenv("PATH");
    size_t tools_len;
    size_t path_len;
    char *combined;
    int rc;

    if (!fixture || fixture->tools[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    if (!retain_existing || !path || path[0] == '\0') {
        return setenv("PATH", fixture->tools, 1);
    }
    tools_len = strlen(fixture->tools);
    path_len = strlen(path);
    if (path_len > SIZE_MAX - tools_len - 2U) {
        errno = EOVERFLOW;
        return -1;
    }
    combined = malloc(tools_len + path_len + 2U);
    if (!combined) return -1;
    memcpy(combined, fixture->tools, tools_len);
    combined[tools_len] = ':';
    memcpy(combined + tools_len + 1U, path, path_len + 1U);
    rc = setenv("PATH", combined, 1);
    free(combined);
    return rc;
}

static int m20_install_private_tools(m20_fixture_t *fixture) {
    if (m20_create_private_tool_copies(
            fixture, g_self_executable, g_self_executable) != 0) {
        return -1;
    }
    if (m20_use_private_tools_path(fixture, false) != 0) {
        int saved_errno = errno ? errno : EIO;

        m20_remove_private_tools(fixture);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

/* Homebrew intentionally lives below a group-writable prefix that production
 * must reject. For the one test that exercises a real retained GPG agent,
 * locate the provisioned bytes without executing them; private copies are
 * then resolved and launched through the normal production trust boundary. */
static int m20_find_provisioned_tool(const char *name, char *output,
                                     size_t output_size) {
    const char *path = getenv("PATH");
    const char *cursor;
    size_t name_len;

    if (!name || !*name || !output || output_size == 0U) {
        errno = EINVAL;
        return -1;
    }
    if (!path) {
        errno = ENOENT;
        return -1;
    }
    name_len = strlen(name);
    cursor = path;
    while (true) {
        const char *separator = strchr(cursor, ':');
        size_t directory_len = separator
                                   ? (size_t)(separator - cursor)
                                   : strlen(cursor);

        if (directory_len > 0U &&
            directory_len <= SIZE_MAX - name_len - 2U &&
            directory_len + name_len + 2U <= output_size &&
            directory_len + name_len + 2U <= MAX_PATH_LEN) {
            char candidate[MAX_PATH_LEN];
            char resolved[MAX_PATH_LEN];
            struct stat st;

            memcpy(candidate, cursor, directory_len);
            candidate[directory_len] = '/';
            memcpy(candidate + directory_len + 1U, name, name_len + 1U);
            if (realpath(candidate, resolved) &&
                stat(resolved, &st) == 0 && S_ISREG(st.st_mode) &&
                (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0 &&
                access(resolved, X_OK) == 0 &&
                safe_strncpy(output, resolved, output_size) == 0) {
                return 0;
            }
        }
        if (!separator) break;
        cursor = separator + 1;
    }
    errno = ENOENT;
    return -1;
}

/* Return 0 when real tools are ready, 1 when the host has none, and -1 for a
 * fixture failure. The caller owns PATH restoration and fixture cleanup. */
static int m20_prepare_live_tools(m20_fixture_t *fixture) {
    char gpgconf_source[MAX_PATH_LEN];
    char connect_source[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];

    if (find_command_path("gpgconf", resolved, sizeof(resolved)) == 0 &&
        find_command_path("gpg-connect-agent", resolved,
                          sizeof(resolved)) == 0) {
        return 0;
    }
    if (m20_find_provisioned_tool("gpgconf", gpgconf_source,
                                  sizeof(gpgconf_source)) != 0 ||
        m20_find_provisioned_tool("gpg-connect-agent", connect_source,
                                  sizeof(connect_source)) != 0) {
        return 1;
    }
    if (m20_create_private_tool_copies(
            fixture, gpgconf_source, connect_source) != 0 ||
        m20_use_private_tools_path(fixture, true) != 0) {
        return -1;
    }
    if (find_command_path("gpgconf", resolved, sizeof(resolved)) != 0 ||
        strcmp(resolved, fixture->gpgconf) != 0 ||
        find_command_path("gpg-connect-agent", resolved,
                          sizeof(resolved)) != 0 ||
        strcmp(resolved, fixture->gpg_connect_agent) != 0) {
        errno = errno ? errno : ENOEXEC;
        return -1;
    }
    return 0;
}

static int m20_make_fixture(m20_fixture_t *fixture,
                            const char *initial_config,
                            bool private_tools) {
    if (!fixture || !initial_config) return -1;
    memset(fixture, 0, sizeof(*fixture));
    if (safe_strncpy(fixture->root, "/tmp/gswar11reload_XXXXXX",
                     sizeof(fixture->root)) != 0 ||
        !ts_mkdtemp(fixture->root) ||
        ts_canonicalize_dir_path(fixture->root,
                                 sizeof(fixture->root)) != 0 ||
        chmod(fixture->root, 0700) != 0 ||
        safe_snprintf(fixture->base, sizeof(fixture->base),
                      "%s/gitswitch-gpg", fixture->root) != 0 ||
        safe_snprintf(fixture->home, sizeof(fixture->home), "%s/reload",
                      fixture->base) != 0 ||
        safe_snprintf(fixture->current, sizeof(fixture->current),
                      "%s/current", fixture->base) != 0 ||
        safe_snprintf(fixture->source_home,
                      sizeof(fixture->source_home), "%s/source",
                      fixture->root) != 0 ||
        safe_snprintf(fixture->source_config,
                      sizeof(fixture->source_config), "%s/gpg-agent.conf",
                      fixture->source_home) != 0 ||
        safe_snprintf(fixture->installed_config,
                      sizeof(fixture->installed_config),
                      "%s/gpg-agent.conf", fixture->home) != 0 ||
        safe_snprintf(fixture->reload_state,
                      sizeof(fixture->reload_state),
                      "%s/.gitswitch-gpg-agent-reload.state",
                      fixture->home) != 0 ||
        mkdir(fixture->source_home, 0700) != 0 ||
        write_string_to_file(fixture->source_config, initial_config,
                             0600) != 0 ||
        setenv("XDG_RUNTIME_DIR", fixture->root, 1) != 0 ||
        setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1) != 0 ||
        setenv("GNUPGHOME", fixture->source_home, 1) != 0) {
        return -1;
    }
    if (private_tools && m20_install_private_tools(fixture) != 0) return -1;

    safe_strncpy(fixture->account.name, "reload",
                 sizeof(fixture->account.name));
    safe_strncpy(fixture->account.email, "reload@example.test",
                 sizeof(fixture->account.email));
    safe_strncpy(fixture->account.gpg_key_id, "FEEDFACE01234567",
                 sizeof(fixture->account.gpg_key_id));
    fixture->account.gpg_enabled = true;
    fixture->account.gpg_signing_enabled = true;
    return 0;
}

static void m20_prepare_config(gpg_config_t *config) {
    memset(config, 0, sizeof(*config));
    config->mode = GPG_MODE_ISOLATED;
    /* The runner models the child, so a pre-bound absolute test spelling
     * avoids coupling these deterministic tests to the host's key tools. */
    safe_strncpy(config->executable_path, "/test/gpg",
                 sizeof(config->executable_path));
}

static bool m20_identity_is_unpublished(const gpg_config_t *config,
                                        const m20_fixture_t *fixture) {
    struct stat st;

    if (!config || !fixture || config->current_key_id[0] != '\0' ||
        config->signing_enabled || config->environment_installed ||
        config->published_link_valid || config->runtime_restore_pending) {
        return false;
    }
    errno = 0;
    return lstat(fixture->current, &st) != 0 && errno == ENOENT;
}

TEST(changed_and_unchanged_config_reload_exactly_once) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat first;
    struct stat second;
    struct stat third;
    int first_rc;
    int second_rc;
    int third_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, true), 0);
    m20_prepare_config(&config);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);

    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    CHECK_EQ_INT(first_rc, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &first), 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);

    second_rc = gpg_create_isolated_home(&config, &fixture.account);
    CHECK_EQ_INT(second_rc, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &second), 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(first.st_ino, second.st_ino);

    CHECK_EQ_INT(write_string_to_file(fixture.source_config,
                                      m20_config_b, 0600), 0);
    g_expected_reload_config = m20_config_b;
    third_rc = gpg_create_isolated_home(&config, &fixture.account);
    CHECK_EQ_INT(third_rc, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &third), 0);
    CHECK_EQ_INT(g_config_commits, 2);
    CHECK_EQ_INT(g_reload_calls, 2);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK(first.st_dev != third.st_dev || first.st_ino != third.st_ino);

    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(reload_failure_prevents_activation_and_identity_publication) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    command_runner_fn old_runner;
    gpg_config_t config;
    char installed[256];
    int switch_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, true), 0);
    m20_prepare_config(&config);
    m20_reset_observation(&fixture, m20_config_a, true);
    old_runner = run_set_runner(m20_runner);
    switch_rc = gpg_switch_account(&config, &fixture.account);
    run_set_runner(old_runner);

    CHECK_EQ_INT(switch_rc, -1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 0);
    CHECK(m20_identity_is_unpublished(&config, &fixture));
    CHECK_STR_EQ(getenv("GNUPGHOME"), fixture.source_home);
    CHECK_EQ_INT(read_file_to_string(fixture.installed_config, installed,
                                     sizeof(installed)),
                 (int)(sizeof(m20_config_a) - 1U));
    CHECK_STR_EQ(installed, m20_config_a);

    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(config_write_failure_prevents_activation_and_identity_publication) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_sync_fn old_sync;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat st;
    int switch_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, true), 0);
    m20_prepare_config(&config);
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(1, 0);
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    old_runner = run_set_runner(m20_runner);
    switch_rc = gpg_switch_account(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);

    CHECK_EQ_INT(switch_rc, -1);
    CHECK_EQ_INT(g_sync_file_calls, 1);
    CHECK_EQ_INT(g_sync_directory_calls, 0);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 0);
    CHECK(m20_identity_is_unpublished(&config, &fixture));
    errno = 0;
    CHECK(lstat(fixture.installed_config, &st) != 0 && errno == ENOENT);
    CHECK_STR_EQ(getenv("GNUPGHOME"), fixture.source_home);

    CHECK_EQ_INT(gpg_manager_cleanup(&config), 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(post_rename_sync_failure_is_retried_without_rewriting_config) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_sync_fn old_sync;
    command_runner_fn old_runner;
    gpg_config_t first;
    gpg_config_t retry;
    struct stat before;
    struct stat after;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, true), 0);
    m20_prepare_config(&first);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 2);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_switch_account(&first, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_sync_directory_calls, 2);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 0);
    CHECK(m20_identity_is_unpublished(&first, &fixture));
    CHECK_EQ_INT(stat(fixture.installed_config, &before), 0);

    m20_prepare_config(&retry);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    old_runner = run_set_runner(m20_runner);
    retry_rc = gpg_switch_account(&retry, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 1);
    CHECK_EQ_INT(stat(fixture.installed_config, &after), 0);
    CHECK_EQ_INT(before.st_ino, after.st_ino);
    CHECK_STR_EQ(retry.current_key_id, M20_PRIMARY_FPR);
    CHECK(retry.signing_enabled);

    CHECK_EQ_INT(gpg_manager_cleanup(&retry), 0);
    CHECK_EQ_INT(gpg_manager_cleanup(&first), 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(clean_state_sync_failure_blocks_publication_and_retries_safely) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    gpg_agent_conf_sync_fn old_sync;
    command_runner_fn old_runner;
    gpg_config_t first;
    gpg_config_t retry;
    struct stat before;
    struct stat after;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, true), 0);
    m20_prepare_config(&first);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    /* Config temp, pending obligation, then completed-state persistence. */
    m20_reset_sync_faults(3, 0);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_switch_account(&first, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_sync_file_calls, 3);
    CHECK_EQ_INT(g_sync_directory_calls, 2);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 0);
    CHECK(m20_identity_is_unpublished(&first, &fixture));
    CHECK_EQ_INT(stat(fixture.installed_config, &before), 0);

    m20_prepare_config(&retry);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    m20_reset_sync_faults(0, 0);
    old_sync = gpg_manager_set_agent_conf_sync_fn(m20_selective_sync);
    old_runner = run_set_runner(m20_runner);
    retry_rc = gpg_switch_account(&retry, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_sync_fn(old_sync);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(g_sync_file_calls, 0);
    CHECK_EQ_INT(g_sync_directory_calls, 1);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 1);
    CHECK_EQ_INT(stat(fixture.installed_config, &after), 0);
    CHECK_EQ_INT(before.st_ino, after.st_ino);
    CHECK_STR_EQ(retry.current_key_id, M20_PRIMARY_FPR);
    CHECK(retry.signing_enabled);

    CHECK_EQ_INT(gpg_manager_cleanup(&retry), 0);
    CHECK_EQ_INT(gpg_manager_cleanup(&first), 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

static int m20_failed_attempt_in_child(const m20_fixture_t *fixture) {
    command_runner_fn old_runner;
    gpg_config_t config;
    int rc;

    m20_prepare_config(&config);
    g_config_commits = 0;
    m20_reset_observation(fixture, m20_config_a, true);
    old_runner = run_set_runner(m20_runner);
    rc = gpg_switch_account(&config, &fixture->account);
    run_set_runner(old_runner);

    if (rc != -1) return 21;
    if (g_reload_calls != 1 || g_reload_protocol_errors != 0) return 22;
    if (g_gpg_listing_calls != 0) return 23;
    if (!m20_identity_is_unpublished(&config, fixture)) return 24;
    if (g_config_commits != 1) return 25;
    return 0;
}

TEST(reload_failure_is_durably_retried_without_rewriting_config) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t retry;
    struct stat before;
    struct stat after;
    char target[MAX_PATH_LEN];
    ssize_t target_len;
    pid_t child;
    int status = 0;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, true), 0);
    g_config_commits = 0;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        _exit(m20_failed_attempt_in_child(&fixture));
    }
    if (child > 0) {
        CHECK_EQ_INT(waitpid(child, &status, 0), child);
        CHECK(WIFEXITED(status));
        if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
    }

    CHECK_EQ_INT(stat(fixture.installed_config, &before), 0);
    CHECK(m20_identity_is_unpublished(&(gpg_config_t){0}, &fixture));

    m20_prepare_config(&retry);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    old_runner = run_set_runner(m20_runner);
    retry_rc = gpg_switch_account(&retry, &fixture.account);
    run_set_runner(old_runner);

    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(g_gpg_listing_calls, 1);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &after), 0);
    CHECK_EQ_INT(before.st_ino, after.st_ino);
    CHECK_STR_EQ(retry.current_key_id, M20_PRIMARY_FPR);
    CHECK(retry.signing_enabled);
    target_len = readlink(fixture.current, target, sizeof(target) - 1U);
    CHECK(target_len > 0 && (size_t)target_len < sizeof(target) - 1U);
    if (target_len > 0 && (size_t)target_len < sizeof(target) - 1U) {
        target[target_len] = '\0';
        CHECK_STR_EQ(target, fixture.home);
    }

    CHECK_EQ_INT(gpg_manager_cleanup(&retry), 0);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(missing_reload_state_for_matching_config_forces_one_migration_reload) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat before;
    struct stat after;
    struct stat state;
    int first_rc;
    int second_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, true), 0);
    CHECK_EQ_INT(mkdir(fixture.base, 0700), 0);
    CHECK_EQ_INT(mkdir(fixture.home, 0700), 0);
    CHECK_EQ_INT(write_string_to_file(fixture.installed_config,
                                      m20_config_a, 0600), 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &before), 0);
    errno = 0;
    CHECK(lstat(fixture.reload_state, &state) != 0 && errno == ENOENT);

    m20_prepare_config(&config);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);
    second_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(first_rc, 0);
    CHECK_EQ_INT(second_rc, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &after), 0);
    CHECK_EQ_INT(before.st_ino, after.st_ino);
    CHECK_EQ_INT(stat(fixture.reload_state, &state), 0);
    CHECK(S_ISREG(state.st_mode));
    CHECK(state.st_size > 0);

    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(corrupt_clean_state_for_matching_config_forces_one_reload) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;
    struct stat before;
    struct stat after;
    int corrupt_rc;
    int clean_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, true), 0);
    m20_prepare_config(&config);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &fixture.account), 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &before), 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);

    CHECK_EQ_INT(write_string_to_file(fixture.reload_state,
                                      "not-a-clean-record\n", 0600), 0);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    corrupt_rc = gpg_create_isolated_home(&config, &fixture.account);
    clean_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(corrupt_rc, 0);
    CHECK_EQ_INT(clean_rc, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &after), 0);
    CHECK_EQ_INT(before.st_ino, after.st_ino);

    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(stale_clean_state_after_identical_config_replacement_forces_reload) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;
    char replacement[MAX_PATH_LEN];
    struct stat original;
    struct stat replaced;
    struct stat after;
    int stale_rc;
    int clean_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, true), 0);
    m20_prepare_config(&config);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &fixture.account), 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &original), 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);

    CHECK_EQ_INT(safe_snprintf(replacement, sizeof(replacement),
                               "%s/.replacement", fixture.home), 0);
    CHECK_EQ_INT(write_string_to_file(replacement, m20_config_a, 0600), 0);
    CHECK_EQ_INT(rename(replacement, fixture.installed_config), 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &replaced), 0);
    CHECK(original.st_dev != replaced.st_dev ||
          original.st_ino != replaced.st_ino);

    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    stale_rc = gpg_create_isolated_home(&config, &fixture.account);
    clean_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(stale_rc, 0);
    CHECK_EQ_INT(clean_rc, 0);
    CHECK_EQ_INT(g_config_commits, 0);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(stat(fixture.installed_config, &after), 0);
    CHECK_EQ_INT(replaced.st_ino, after.st_ino);

    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(exact_ctime_drift_during_reload_is_byte_proved_once) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;
    int first_rc;
    int second_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, true), 0);
    m20_prepare_config(&config);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    g_reload_mutation = M20_RELOAD_MUTATION_EXACT_CTIME;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);

    CHECK_EQ_INT(first_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);

    m20_reset_observation(&fixture, m20_config_a, false);
    second_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(second_rc, 0);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 0);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(changed_bytes_with_restored_mtime_fail_then_retry) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    gpg_agent_conf_precommit_fn old_commit;
    command_runner_fn old_runner;
    gpg_config_t config;
    int first_rc;
    int retry_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_config_a, true), 0);
    m20_prepare_config(&config);
    g_config_commits = 0;
    m20_reset_observation(&fixture, m20_config_a, false);
    g_reload_mutation = M20_RELOAD_MUTATION_DIFFERENT_BYTES;
    old_commit = gpg_manager_set_agent_conf_precommit_fn(
        m20_count_config_commit);
    old_runner = run_set_runner(m20_runner);
    first_rc = gpg_create_isolated_home(&config, &fixture.account);

    CHECK_EQ_INT(first_rc, -1);
    CHECK_EQ_INT(g_config_commits, 1);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK(strstr(get_last_error()->message,
                 "changed during GPG agent activation") != NULL);

    m20_reset_observation(&fixture, m20_config_a, false);
    retry_rc = gpg_create_isolated_home(&config, &fixture.account);
    run_set_runner(old_runner);
    gpg_manager_set_agent_conf_precommit_fn(old_commit);

    CHECK_EQ_INT(retry_rc, 0);
    CHECK_EQ_INT(g_config_commits, 2);
    CHECK_EQ_INT(g_reload_calls, 1);
    CHECK_EQ_INT(g_reload_protocol_errors, 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
}

TEST(changed_config_is_observed_by_the_retained_live_agent) {
    m20_saved_env_t runtime = m20_save_env("XDG_RUNTIME_DIR");
    m20_saved_env_t optin = m20_save_env("GITSWITCH_ALLOW_TMP_GPG");
    m20_saved_env_t gnupg = m20_save_env("GNUPGHOME");
    m20_saved_env_t path = m20_save_env("PATH");
    m20_fixture_t fixture;
    command_runner_fn old_runner;
    gpg_config_t config;
    unsigned long long pid_before = 0;
    unsigned long long pid_after = 0;
    unsigned long long count_before = 0;
    unsigned long long count_after = 0;
    int query_rc;
    int tools_rc;

    CHECK_EQ_INT(m20_make_fixture(&fixture, m20_live_config_a, false), 0);
    tools_rc = m20_prepare_live_tools(&fixture);
    if (tools_rc > 0) {
        CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
        CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
        CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
        CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
        TS_SKIP("gpg", "trusted gpgconf/gpg-connect-agent unavailable");
    }
    if (tools_rc < 0) {
        CHECK_EQ_INT(tools_rc, 0);
        CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
        CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
        CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
        CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
        m20_remove_private_tools(&fixture);
        return;
    }
    m20_prepare_config(&config);

    g_live_reload_calls = 0;
    old_runner = run_set_runner(m20_real_recording_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &fixture.account), 0);
    run_set_runner(old_runner);
    CHECK_EQ_INT(g_live_reload_calls, 1);
    CHECK_EQ_INT(m20_query_agent_number(fixture.home, "GETINFO pid",
                                        &pid_before), 0);
    query_rc = m20_query_agent_number(fixture.home, "GETINFO s2k_count",
                                      &count_before);
    if (query_rc != 0) {
        CHECK_EQ_INT(gpg_manager_reset("reload"), 0);
        CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
        CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
        CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
        CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
        m20_remove_private_tools(&fixture);
        TS_SKIP("gpg", "agent does not expose GETINFO s2k_count");
    }

    CHECK_EQ_INT(write_string_to_file(fixture.source_config,
                                      m20_live_config_b, 0600), 0);
    g_live_reload_calls = 0;
    old_runner = run_set_runner(m20_real_recording_runner);
    CHECK_EQ_INT(gpg_create_isolated_home(&config, &fixture.account), 0);
    run_set_runner(old_runner);
    CHECK_EQ_INT(g_live_reload_calls, 1);
    CHECK_EQ_INT(m20_query_agent_number(fixture.home, "GETINFO pid",
                                        &pid_after), 0);
    CHECK_EQ_INT(m20_query_agent_number(fixture.home, "GETINFO s2k_count",
                                        &count_after), 0);
    CHECK_EQ_INT(pid_before, pid_after);
    CHECK(count_before != count_after);

    CHECK_EQ_INT(gpg_manager_reset("reload"), 0);
    CHECK_EQ_INT(m20_restore_env("GNUPGHOME", &gnupg), 0);
    CHECK_EQ_INT(m20_restore_env("GITSWITCH_ALLOW_TMP_GPG", &optin), 0);
    CHECK_EQ_INT(m20_restore_env("XDG_RUNTIME_DIR", &runtime), 0);
    CHECK_EQ_INT(m20_restore_env("PATH", &path), 0);
    m20_remove_private_tools(&fixture);
}

int main(int argc, char **argv) {
    (void)unsetenv("GNUPGHOME");
    if (argc != 1 || !realpath(argv[0], g_self_executable)) {
        fprintf(stderr,
                "test_ar11_gpg_reload: cannot resolve own executable\n");
        return 2;
    }
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(changed_and_unchanged_config_reload_exactly_once);
    RUN_TEST(reload_failure_prevents_activation_and_identity_publication);
    RUN_TEST(config_write_failure_prevents_activation_and_identity_publication);
    RUN_TEST(post_rename_sync_failure_is_retried_without_rewriting_config);
    RUN_TEST(clean_state_sync_failure_blocks_publication_and_retries_safely);
    RUN_TEST(reload_failure_is_durably_retried_without_rewriting_config);
    RUN_TEST(missing_reload_state_for_matching_config_forces_one_migration_reload);
    RUN_TEST(corrupt_clean_state_for_matching_config_forces_one_reload);
    RUN_TEST(stale_clean_state_after_identical_config_replacement_forces_reload);
    RUN_TEST(exact_ctime_drift_during_reload_is_byte_proved_once);
    RUN_TEST(changed_bytes_with_restored_mtime_fail_then_retry);
    RUN_TEST(changed_config_is_observed_by_the_retained_live_agent);
    return ts_test_finish();
}
