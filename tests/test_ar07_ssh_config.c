/* AR-07 T9: adversarial SSH user-config serialization and replacement. */
#ifdef __linux__
#define _GNU_SOURCE
#endif

#include "test.h"
#include "error.h"
#include "gitswitch.h"
#include "scratch_registry_test.h"
#include "ssh_manager.h"
#define GITSWITCH_INTERNAL_API
#include "ssh_manager_internal.h"
#undef GITSWITCH_INTERNAL_API
#include "utils.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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

#define TEST_ALIAS "github-work"
#define TEST_HOSTNAME "github.com"
#define TEST_ALIAS_TWO "gitlab-personal"
#define TEST_HOSTNAME_TWO "gitlab.com"
#define BEGIN_MARK "# >>> gitswitch " TEST_ALIAS " >>>"
#define END_MARK "# <<< gitswitch " TEST_ALIAS " <<<"

static int g_dirsync_calls;
#define DIRSYNC_OBSERVATION_MAX 4
static struct stat g_dirsync_observations[DIRSYNC_OBSERVATION_MAX];
static size_t g_dirsync_observation_count;
static struct stat g_expected_home_identity;
static bool g_fail_home_dirsync;
static char g_public_home_link[MAX_PATH_LEN];
static char g_replacement_home[MAX_PATH_LEN];
static bool g_home_create_retarget_succeeded;
static char g_public_ssh_dir[MAX_PATH_LEN];
static char g_moved_ssh_dir[MAX_PATH_LEN];
static int g_transaction_ready_fd = -1;
static int g_transaction_release_fd = -1;
static int g_transaction_commit_fd = -1;
static int g_identical_commit_hook_calls;
static int g_identical_postrename_hook_calls;
static char g_unchanged_recheck_config[MAX_PATH_LEN];
static int g_unchanged_recheck_hook_calls;
static bool g_unchanged_recheck_chmod_succeeded;
static int g_unchanged_final_recheck_hook_calls;
static bool g_unchanged_final_recheck_swap_succeeded;

static int setup_home_without_ssh(char home[96],
                                  char config[MAX_PATH_LEN]) {
    snprintf(home, 96, "/tmp/gswar07sshcfgXXXXXX");
    if (!ts_mkdtemp(home) || setenv("HOME", home, 1) != 0) return -1;
    if ((size_t)snprintf(config, MAX_PATH_LEN, "%s/.ssh/config", home) >=
        MAX_PATH_LEN) {
        return -1;
    }
    return 0;
}

static int setup_home(char home[96], char config[MAX_PATH_LEN]) {
    char ssh_dir[MAX_PATH_LEN];

    if (setup_home_without_ssh(home, config) != 0 ||
        (size_t)snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home) >=
            sizeof(ssh_dir) ||
        mkdir(ssh_dir, 0700) != 0) {
        return -1;
    }
    return 0;
}

static int setup_symlinked_home(char root[96],
                                char real_home[MAX_PATH_LEN],
                                char public_home[MAX_PATH_LEN],
                                char config[MAX_PATH_LEN]) {
    snprintf(root, 96, "/tmp/gswar07sshlinkXXXXXX");
    if (!ts_mkdtemp(root) ||
        (size_t)snprintf(real_home, MAX_PATH_LEN, "%s/real", root) >=
            MAX_PATH_LEN ||
        (size_t)snprintf(public_home, MAX_PATH_LEN, "%s/home", root) >=
            MAX_PATH_LEN ||
        mkdir(real_home, 0700) != 0 ||
        symlink(real_home, public_home) != 0 ||
        setenv("HOME", public_home, 1) != 0 ||
        (size_t)snprintf(config, MAX_PATH_LEN, "%s/.ssh/config",
                         public_home) >= MAX_PATH_LEN) {
        return -1;
    }
    return 0;
}

static void make_account(account_t *account, const char *key_path) {
    memset(account, 0, sizeof(*account));
    account->ssh_enabled = true;
    snprintf(account->ssh_host_alias, sizeof(account->ssh_host_alias), "%s",
             TEST_ALIAS);
    snprintf(account->ssh_hostname, sizeof(account->ssh_hostname), "%s",
             TEST_HOSTNAME);
    snprintf(account->ssh_key_path, sizeof(account->ssh_key_path), "%s",
             key_path);
}

static int write_bytes(const char *path, const void *bytes, size_t length) {
    size_t written = 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

    if (fd < 0) return -1;
    while (written < length) {
        ssize_t n = write(fd, (const char *)bytes + written, length - written);
        if (n > 0) written += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else {
            close(fd);
            return -1;
        }
    }
    return close(fd);
}

static char *read_bytes(const char *path, size_t *length) {
    struct stat st;
    char *buf;
    size_t used = 0;
    int fd;

    if (stat(path, &st) != 0 || st.st_size < 0) return NULL;
    buf = malloc((size_t)st.st_size + 1U);
    if (!buf) return NULL;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        free(buf);
        return NULL;
    }
    while (used < (size_t)st.st_size) {
        ssize_t n = read(fd, buf + used, (size_t)st.st_size - used);
        if (n > 0) used += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else break;
    }
    if (close(fd) != 0 || used != (size_t)st.st_size) {
        free(buf);
        return NULL;
    }
    buf[used] = '\0';
    *length = used;
    return buf;
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

static bool same_ctime(const struct stat *left, const struct stat *right) {
#ifdef __APPLE__
    return left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec &&
           left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    return left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
}

static void check_unchanged(const char *path, const void *expected,
                            size_t expected_len, const struct stat *before) {
    struct stat after;
    size_t actual_len = 0;
    char *actual = read_bytes(path, &actual_len);

    CHECK(actual != NULL);
    if (actual) {
        CHECK_EQ_INT(actual_len, expected_len);
        CHECK(actual_len != expected_len ||
              memcmp(actual, expected, expected_len) == 0);
    }
    CHECK_EQ_INT(stat(path, &after), 0);
    CHECK(before->st_dev == after.st_dev);
    CHECK(before->st_ino == after.st_ino);
    CHECK(same_mtime(before, &after));
    free(actual);
}

static void check_alias_conflict_rejected_before_publication(
    const char *config, const char *original, size_t original_len,
    const account_t *account) {
    struct stat before;
    ssh_config_publication_state_t publication =
        SSH_CONFIG_PUBLICATION_COMMITTED;

    CHECK_EQ_INT(stat(config, &before), 0);
    CHECK_EQ_INT(ssh_preflight_host_alias_config(account), -1);
    check_unchanged(config, original, original_len, &before);

    CHECK_EQ_INT(ssh_configure_host_alias_result(account, &publication), -1);
    CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_PREINSTALL_FAILED);
    check_unchanged(config, original, original_len, &before);
}

static void check_alias_config_permitted_without_mutation(
    const char *config, const char *original, size_t original_len,
    const account_t *account) {
    struct stat before;

    CHECK_EQ_INT(stat(config, &before), 0);
    CHECK_EQ_INT(ssh_preflight_host_alias_config(account), 0);
    check_unchanged(config, original, original_len, &before);
}

static size_t count_text(const char *haystack, const char *needle) {
    size_t count = 0;
    size_t needle_len = strlen(needle);
    const char *p = haystack;
    while ((p = strstr(p, needle)) != NULL) {
        count++;
        p += needle_len;
    }
    return count;
}

static size_t count_temps_in(const char *dir_path) {
    DIR *dir = opendir(dir_path);
    struct dirent *entry;
    size_t count = 0;
    if (!dir) return 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "config.gitswitch.", 17) == 0) count++;
    }
    closedir(dir);
    return count;
}

typedef struct {
    char home[96];
    char config[MAX_PATH_LEN];
    char ssh_dir[MAX_PATH_LEN];
    account_t account;
    struct stat home_identity;
    struct stat ssh_identity;
    struct stat config_identity;
    char *content;
    size_t content_len;
    int open_fds;
} identical_config_fixture_t;

static int setup_identical_config_fixture(identical_config_fixture_t *fixture,
                                          mode_t mode) {
    char key[MAX_PATH_LEN];

    memset(fixture, 0, sizeof(*fixture));
    if (setup_home(fixture->home, fixture->config) != 0 ||
        (size_t)snprintf(fixture->ssh_dir, sizeof(fixture->ssh_dir),
                         "%s/.ssh", fixture->home) >=
            sizeof(fixture->ssh_dir) ||
        (size_t)snprintf(key, sizeof(key), "%s/id", fixture->home) >=
            sizeof(key)) {
        return -1;
    }
    make_account(&fixture->account, key);
    if (ssh_configure_host_alias(&fixture->account) != 0 ||
        chmod(fixture->config, mode) != 0 ||
        stat(fixture->home, &fixture->home_identity) != 0 ||
        stat(fixture->ssh_dir, &fixture->ssh_identity) != 0 ||
        stat(fixture->config, &fixture->config_identity) != 0) {
        return -1;
    }
    fixture->content = read_bytes(fixture->config, &fixture->content_len);
    if (!fixture->content) return -1;
    fixture->open_fds = test_open_fd_count();
    return 0;
}

static void check_exact_file_bytes(const char *path, const char *expected,
                                   size_t expected_len) {
    size_t actual_len = 0;
    char *actual = read_bytes(path, &actual_len);

    CHECK(actual != NULL);
    if (actual) {
        CHECK_EQ_INT(actual_len, expected_len);
        CHECK(actual_len != expected_len ||
              memcmp(actual, expected, expected_len) == 0);
    }
    free(actual);
}

static void check_identical_fixture_clean(identical_config_fixture_t *fixture) {
    CHECK_EQ_INT(count_temps_in(fixture->ssh_dir), 0);
    CHECK_EQ_INT(test_open_fd_count(), fixture->open_fds);
    free(fixture->content);
    fixture->content = NULL;
}

static bool output_has_value(const char *output, const char *keyword,
                             const char *expected) {
    size_t keyword_len = strlen(keyword);
    const char *line = output;

    while (*line) {
        const char *end = strchr(line, '\n');
        size_t line_len = end ? (size_t)(end - line) : strlen(line);
        if (line_len > keyword_len + 1U &&
            memcmp(line, keyword, keyword_len) == 0 &&
            line[keyword_len] == ' ' &&
            line_len - keyword_len - 1U == strlen(expected) &&
            memcmp(line + keyword_len + 1U, expected, strlen(expected)) == 0) {
            return true;
        }
        if (!end) break;
        line = end + 1;
    }
    return false;
}

static int fail_dirsync(int dir_fd) {
    (void)dir_fd;
    g_dirsync_calls++;
    errno = EIO;
    return -1;
}

static void reset_dirsync_observations(const struct stat *home_identity,
                                       bool fail_home) {
    memset(g_dirsync_observations, 0, sizeof(g_dirsync_observations));
    g_dirsync_observation_count = 0;
    g_expected_home_identity = *home_identity;
    g_fail_home_dirsync = fail_home;
}

static int observe_dirsync(int dir_fd) {
    struct stat identity;

    if (fstat(dir_fd, &identity) != 0) return -1;
    if (g_dirsync_observation_count >= DIRSYNC_OBSERVATION_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    g_dirsync_observations[g_dirsync_observation_count++] = identity;
    if (g_fail_home_dirsync &&
        ts_same_identity(&identity, &g_expected_home_identity)) {
        errno = EIO;
        return -1;
    }
    return fsync(dir_fd);
}

static int retarget_home_during_dirsync(int dir_fd) {
    struct stat identity;

    if (fstat(dir_fd, &identity) != 0) return -1;
    if (g_dirsync_observation_count >= DIRSYNC_OBSERVATION_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    g_dirsync_observations[g_dirsync_observation_count++] = identity;
    if (ts_same_identity(&identity, &g_expected_home_identity)) {
        if (unlink(g_public_home_link) != 0 ||
            symlink(g_replacement_home, g_public_home_link) != 0) {
            return -1;
        }
    }
    return fsync(dir_fd);
}

static bool retarget_home_before_ssh_create(
    ssh_metadata_test_stage_t stage) {
    if (stage != SSH_METADATA_TEST_CONFIG_HOME_CREATE) return false;
    g_home_create_retarget_succeeded =
        unlink(g_public_home_link) == 0 &&
        symlink(g_replacement_home, g_public_home_link) == 0;
    return false;
}

static bool make_config_writable_before_unchanged_recheck(
    ssh_metadata_test_stage_t stage) {
    if (stage != SSH_METADATA_TEST_CONFIG_UNCHANGED_RECHECK) return false;
    g_unchanged_recheck_hook_calls++;
    g_unchanged_recheck_chmod_succeeded =
        chmod(g_unchanged_recheck_config, 0666) == 0;
    return false;
}

static int fail_postrename_verification(int dir_fd) {
    (void)dir_fd;
    errno = EIO;
    return -1;
}

static int fail_identical_config_commit(int dir_fd, const char *temp_name) {
    (void)dir_fd;
    (void)temp_name;
    g_identical_commit_hook_calls++;
    errno = EIO;
    return -1;
}

static int fail_identical_postrename_verification(int dir_fd) {
    (void)dir_fd;
    g_identical_postrename_hook_calls++;
    errno = EIO;
    return -1;
}

static int swap_public_ssh_directory(int dir_fd, const char *temp_name) {
    static const char replacement[] = "Host replacement\n  User untouched\n";
    char config[MAX_PATH_LEN];
    (void)dir_fd;
    (void)temp_name;

    if (rename(g_public_ssh_dir, g_moved_ssh_dir) != 0 ||
        mkdir(g_public_ssh_dir, 0700) != 0 ||
        (size_t)snprintf(config, sizeof(config), "%s/config",
                         g_public_ssh_dir) >= sizeof(config) ||
        write_bytes(config, replacement, sizeof(replacement) - 1U) != 0) {
        return -1;
    }
    return 0;
}

static bool swap_ssh_directory_before_unchanged_final_recheck(
    ssh_metadata_test_stage_t stage) {
    if (stage != SSH_METADATA_TEST_CONFIG_UNCHANGED_FINAL_RECHECK) {
        return false;
    }
    g_unchanged_final_recheck_hook_calls++;
    g_unchanged_final_recheck_swap_succeeded =
        swap_public_ssh_directory(-1, NULL) == 0;
    return false;
}

static int write_marker(int fd, char marker) {
    for (;;) {
        ssize_t written = write(fd, &marker, 1);
        if (written == 1) return 0;
        if (written < 0 && errno == EINTR) continue;
        return -1;
    }
}

static int read_marker(int fd) {
    char marker;
    for (;;) {
        ssize_t received = read(fd, &marker, 1);
        if (received == 1) return 0;
        if (received < 0 && errno == EINTR) continue;
        return -1;
    }
}

static int wait_readable(int fd, int timeout_ms) {
    struct pollfd descriptor = { .fd = fd, .events = POLLIN, .revents = 0 };
    int result;

    do {
        result = poll(&descriptor, 1, timeout_ms);
    } while (result < 0 && errno == EINTR);
    if (result <= 0) return result;
    return (descriptor.revents & (POLLIN | POLLHUP)) != 0 ? 1 : -1;
}

static int wait_child(pid_t child, int *status, int timeout_ms) {
    int elapsed = 0;

    while (elapsed < timeout_ms) {
        pid_t waited = waitpid(child, status, WNOHANG);
        if (waited == child) return 0;
        if (waited < 0 && errno != EINTR) return -1;
        (void)poll(NULL, 0, 10);
        elapsed += 10;
    }
    (void)kill(child, SIGKILL);
    while (waitpid(child, status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    errno = ETIMEDOUT;
    return -1;
}

static void close_test_fd(int *fd) {
    if (*fd >= 0) {
        (void)close(*fd);
        *fd = -1;
    }
}

static int pause_while_holding_config_transaction(int dir_fd,
                                                   const char *temp_name) {
    (void)dir_fd;
    (void)temp_name;
    if (write_marker(g_transaction_ready_fd, '1') != 0 ||
        read_marker(g_transaction_release_fd) != 0) {
        return -1;
    }
    return 0;
}

static int report_config_commit(int dir_fd, const char *temp_name) {
    (void)dir_fd;
    (void)temp_name;
    return write_marker(g_transaction_commit_fd, '2');
}

static int advance_config_ctime_without_changing_bytes(int dir_fd,
                                                        const char *temp_name) {
    struct stat before;
    struct stat after;
    (void)temp_name;

    if (fstatat(dir_fd, "config", &before, AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    for (int attempt = 0; attempt < 10; attempt++) {
        if (fchmodat(dir_fd, "config", before.st_mode & 0777, 0) != 0 ||
            fstatat(dir_fd, "config", &after, AT_SYMLINK_NOFOLLOW) != 0) {
            return -1;
        }
        if (!same_ctime(&before, &after)) return 0;
        (void)poll(NULL, 0, 1);
    }
    errno = EIO;
    return -1;
}

static int replace_config_byte_preserving_mtime(int dir_fd,
                                                 const char *temp_name) {
    struct stat before;
    struct timespec times[2];
    unsigned char byte;
    int fd;
    (void)temp_name;

    fd = openat(dir_fd, "config", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &before) != 0 ||
        pread(fd, &byte, 1, 0) != 1) {
        if (fd >= 0) close(fd);
        return -1;
    }
    byte ^= 1U;
    if (pwrite(fd, &byte, 1, 0) != 1) {
        close(fd);
        return -1;
    }
#ifdef __APPLE__
    times[0] = before.st_atimespec;
    times[1] = before.st_mtimespec;
#else
    times[0] = before.st_atim;
    times[1] = before.st_mtim;
#endif
    if (futimens(fd, times) != 0 || fsync(fd) != 0) {
        close(fd);
        return -1;
    }
    return close(fd);
}

TEST(identityfile_quoting_and_hostname_are_serialized_safely) {
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;
    size_t config_len = 0;
    char *content;

    CHECK_EQ_INT(setup_home(home, config), 0);
    snprintf(key, sizeof(key), "%s/key dir/id\\backslash", home);
    make_account(&account, key);
    CHECK_EQ_INT(ssh_configure_host_alias(&account), 0);
    content = read_bytes(config, &config_len);
    CHECK(content != NULL);
    if (content) {
        CHECK(strstr(content, "HostName " TEST_HOSTNAME "\n") != NULL);
        CHECK(strstr(content, "IdentityFile \"") != NULL);
        CHECK(strstr(content, "key dir/id\\backslash\"") != NULL);
        free(content);
    }
}

TEST(host_port_hostname_is_rejected_without_mutating_config) {
    static const char original[] = "Host preserved\n  User alice\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;
    struct stat before;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    CHECK_EQ_INT(stat(config, &before), 0);
    snprintf(key, sizeof(key), "%s/id_endpoint", home);
    make_account(&account, key);
    CHECK_EQ_INT(safe_strncpy(account.ssh_hostname,
                              "git.example.test:2222",
                              sizeof(account.ssh_hostname)), 0);

    CHECK_EQ_INT(ssh_configure_host_alias(&account), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_INVALID_ARGS);
    check_unchanged(config, original, sizeof(original) - 1U, &before);
}

TEST(historical_host_port_block_can_be_repaired_after_upgrade) {
    static const char historical[] =
        BEGIN_MARK "\n"
        "Host " TEST_ALIAS "\n"
        "  HostName git.example.test:2222\n"
        "  IdentityFile \"/old/key\"\n"
        "  IdentitiesOnly yes\n"
        END_MARK "\n"
        "# >>> gitswitch other-work >>>\n"
        "Host other-work\n"
        "  HostName other.example:2200\n"
        "  IdentityFile \"/old/other-key\"\n"
        "  IdentitiesOnly yes\n"
        "# <<< gitswitch other-work <<<\n"
        "Host preserved\n  User alice\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;
    size_t content_len = 0U;
    char *content;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, historical, sizeof(historical) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id_repaired", home);
    make_account(&account, key);
    CHECK_EQ_INT(safe_strncpy(account.ssh_hostname, "git.example.test",
                              sizeof(account.ssh_hostname)), 0);

    CHECK_EQ_INT(ssh_configure_host_alias(&account), 0);
    content = read_bytes(config, &content_len);
    CHECK(content != NULL);
    if (content) {
        CHECK(strstr(content, "Host preserved\n  User alice\n") != NULL);
        CHECK(strstr(content, "HostName git.example.test:2222") == NULL);
        CHECK(strstr(content, "  HostName git.example.test\n") != NULL);
        CHECK(strstr(content, key) != NULL);
        CHECK(strstr(content, "  HostName other.example:2200\n") != NULL);
        CHECK(strstr(content, "  IdentityFile \"/old/other-key\"\n") !=
              NULL);
        CHECK_EQ_INT(count_text(content, BEGIN_MARK), 1);
        CHECK_EQ_INT(count_text(content, END_MARK), 1);
        free(content);
    }
}

TEST(historical_host_port_block_can_be_removed_after_upgrade) {
    static const char historical[] =
        "Host preserved\n  User alice\n"
        BEGIN_MARK "\n"
        "Host " TEST_ALIAS "\n"
        "  HostName git.example.test:2222\n"
        "  IdentityFile \"/old/key\"\n"
        "  IdentitiesOnly yes\n"
        END_MARK "\n"
        "Host tail\n  User bob\n";
    char home[96], config[MAX_PATH_LEN];
    size_t content_len = 0U;
    char *content;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, historical, sizeof(historical) - 1U), 0);
    CHECK_EQ_INT(ssh_remove_host_alias(TEST_ALIAS), 0);
    content = read_bytes(config, &content_len);
    CHECK(content != NULL);
    if (content) {
        CHECK(strstr(content, BEGIN_MARK) == NULL);
        CHECK(strstr(content, END_MARK) == NULL);
        CHECK(strstr(content, "git.example.test:2222") == NULL);
        CHECK(strstr(content, "Host preserved\n  User alice\n") != NULL);
        CHECK(strstr(content, "Host tail\n  User bob\n") != NULL);
        free(content);
    }
}

TEST(identityfile_quoting_and_hostname_match_openssh_oracle) {
    static const char ipv6_hostname[] = "2001:db8::1";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    char output[32768];
    account_t account;
    run_opts_t opts;
    run_result_t result;

    if (!command_exists("ssh")) {
        TS_SKIP("openssh", "ssh unavailable in trusted PATH");
    }
    CHECK_EQ_INT(setup_home(home, config), 0);
    snprintf(key, sizeof(key), "%s/key dir/id\\backslash", home);
    make_account(&account, key);
    CHECK_EQ_INT(safe_strncpy(account.ssh_hostname, ipv6_hostname,
                              sizeof(account.ssh_hostname)), 0);
    CHECK_EQ_INT(ssh_configure_host_alias(&account), 0);
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.merge_stderr = true;
    {
        const char *const argv[] = {
            "ssh", "-G", "-F", config, TEST_ALIAS, NULL
        };
        CHECK_EQ_INT(run_argv(argv, &opts, &result), 0);
    }
    CHECK(!result.out_truncated);
    CHECK(output_has_value(output, "hostname", ipv6_hostname));
    CHECK(output_has_value(output, "port", "22"));
    CHECK(output_has_value(output, "identityfile", key));
}

TEST(openssh_include_rejects_other_writable_config) {
    static const mode_t accepted_modes[] = {0600, 0644};
    /* Debian and Ubuntu intentionally accept group-write when the owning
     * group contains only the file owner. Other-write remains an invariant
     * across their policy and upstream OpenSSH. The application's stricter
     * no-group/no-other-write policy has a separate causal mode matrix. */
    static const mode_t rejected_modes[] = {0602, 0666};
    static const char included_text[] =
        "Host l36-probe\n"
        "  HostName l36.example.test\n"
        "  User l36-user\n";
    static const char *const clean_locale[] = {"LC_ALL=C", NULL};
    char home[96], included[MAX_PATH_LEN], wrapper[MAX_PATH_LEN];
    char wrapper_text[MAX_PATH_LEN + 16U];
    char output[32768];
    run_opts_t opts;
    run_result_t result;
    int needed;

    if (!command_exists("ssh")) {
        TS_SKIP("openssh", "ssh unavailable in trusted PATH");
    }
    CHECK_EQ_INT(setup_home(home, included), 0);
    CHECK((size_t)snprintf(wrapper, sizeof(wrapper), "%s/.ssh/wrapper",
                           home) < sizeof(wrapper));
    needed = snprintf(wrapper_text, sizeof(wrapper_text), "Include %s\n",
                      included);
    CHECK(needed > 0 && (size_t)needed < sizeof(wrapper_text));
    CHECK_EQ_INT(write_bytes(included, included_text,
                             sizeof(included_text) - 1U), 0);
    CHECK_EQ_INT(write_bytes(wrapper, wrapper_text,
                             needed > 0 ? (size_t)needed : 0U), 0);
    CHECK_EQ_INT(chmod(wrapper, 0600), 0);

    memset(&opts, 0, sizeof(opts));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.merge_stderr = true;
    opts.extra_env = clean_locale;

    for (size_t i = 0;
         i < sizeof(accepted_modes) / sizeof(accepted_modes[0]); i++) {
        const char *const argv[] = {
            "ssh", "-G", "-T", "-F", wrapper, "l36-probe", NULL
        };

        CHECK_EQ_INT(chmod(included, accepted_modes[i]), 0);
        memset(output, 0, sizeof(output));
        memset(&result, 0, sizeof(result));
        CHECK_EQ_INT(run_argv(argv, &opts, &result), 0);
        CHECK(result.spawned);
        CHECK_EQ_INT(result.exit_code, 0);
        CHECK_EQ_INT(result.term_signal, 0);
        CHECK(!result.out_truncated);
        CHECK(output_has_value(output, "hostname", "l36.example.test"));
        CHECK(output_has_value(output, "user", "l36-user"));
    }

    for (size_t i = 0;
         i < sizeof(rejected_modes) / sizeof(rejected_modes[0]); i++) {
        const char *const argv[] = {
            "ssh", "-G", "-T", "-F", wrapper, "l36-probe", NULL
        };

        CHECK_EQ_INT(chmod(included, rejected_modes[i]), 0);
        memset(output, 0, sizeof(output));
        memset(&result, 0, sizeof(result));
        CHECK_EQ_INT(run_argv(argv, &opts, &result), -1);
        CHECK(result.spawned);
        CHECK(result.exit_code != 0);
        CHECK_EQ_INT(result.term_signal, 0);
        CHECK(!result.out_truncated);
        CHECK(strstr(output, "Bad owner or permissions") != NULL);
        CHECK(strstr(output, included) != NULL);
    }
}

TEST(openssh_percent_and_environment_expansions_are_safe) {
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;
    struct stat before;
    static const char original[] = "Host preserved\n  User alice\n";
    size_t length = 0;
    char *content;

    CHECK_EQ_INT(setup_home(home, config), 0);
    snprintf(key, sizeof(key), "%s/id-%%h", home);
    make_account(&account, key);
    CHECK_EQ_INT(ssh_configure_host_alias(&account), 0);
    content = read_bytes(config, &length);
    CHECK(content != NULL);
    if (content) {
        CHECK(strstr(content, "id-%%h\"") != NULL);
        free(content);
    }

    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    CHECK_EQ_INT(stat(config, &before), 0);
    snprintf(key, sizeof(key), "%s/id-${HOME}", home);
    make_account(&account, key);
    CHECK_EQ_INT(ssh_configure_host_alias(&account), -1);
    check_unchanged(config, original, sizeof(original) - 1U, &before);
}

TEST(embedded_nul_at_every_region_fails_without_mutation) {
    static const unsigned char fixtures[][256] = {
        "Host user\n\0before marker\n" BEGIN_MARK "\nHost " TEST_ALIAS
        "\n  IdentityFile /old\n  IdentitiesOnly yes\n" END_MARK "\n",
        BEGIN_MARK "\nHost " TEST_ALIAS "\n  Identity\0File /old\n"
        "  IdentitiesOnly yes\n" END_MARK "\nHost tail\n",
        BEGIN_MARK "\nHost " TEST_ALIAS "\n  IdentityFile /old\n"
        "  IdentitiesOnly yes\n" END_MARK "\nHost tail\n\0after\n"
    };
    static const size_t lengths[] = {
        sizeof("Host user\n\0before marker\n" BEGIN_MARK "\nHost " TEST_ALIAS
               "\n  IdentityFile /old\n  IdentitiesOnly yes\n" END_MARK "\n") - 1U,
        sizeof(BEGIN_MARK "\nHost " TEST_ALIAS "\n  Identity\0File /old\n"
               "  IdentitiesOnly yes\n" END_MARK "\nHost tail\n") - 1U,
        sizeof(BEGIN_MARK "\nHost " TEST_ALIAS "\n  IdentityFile /old\n"
               "  IdentitiesOnly yes\n" END_MARK "\nHost tail\n\0after\n") - 1U
    };

    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
        struct stat before;
        account_t account;
        CHECK_EQ_INT(setup_home(home, config), 0);
        snprintf(key, sizeof(key), "%s/id", home);
        make_account(&account, key);
        CHECK_EQ_INT(write_bytes(config, fixtures[i], lengths[i]), 0);
        CHECK_EQ_INT(stat(config, &before), 0);
        CHECK_EQ_INT(ssh_configure_host_alias(&account), -1);
        CHECK_EQ_INT(ssh_remove_host_alias(TEST_ALIAS), -1);
        check_unchanged(config, fixtures[i], lengths[i], &before);
    }
}

TEST(exact_marker_parser_preserves_incidental_substrings) {
    static const char original[] =
        "# prose mentions " BEGIN_MARK " but is not a marker line\n"
        "Host personal\n  User alice\n";
    char home[96], config[MAX_PATH_LEN];
    struct stat before;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    CHECK_EQ_INT(stat(config, &before), 0);
    CHECK_EQ_INT(ssh_remove_host_alias(TEST_ALIAS), 0);
    check_unchanged(config, original, sizeof(original) - 1U, &before);
}

TEST(earlier_unmanaged_catchall_is_rejected_before_alias_publication) {
    static const char original[] =
        "Host *\n"
        "  HostName catchall.example.test\n"
        "  IdentityFile \"/preserved/catchall-key\"\n"
        "Host preserved\n"
        "  User alice\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_conflict_rejected_before_publication(
        config, original, sizeof(original) - 1U, &account);
}

TEST(earlier_unmanaged_wildcard_match_is_rejected_before_alias_publication) {
    static const char original[] =
        "Host github-*\n"
        "  HostName wildcard.example.test\n"
        "  IdentityFile \"/preserved/wildcard-key\"\n"
        "Host preserved\n"
        "  User alice\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_conflict_rejected_before_publication(
        config, original, sizeof(original) - 1U, &account);
}

TEST(earlier_unmanaged_second_whitespace_pattern_is_rejected_before_publication) {
    static const char original[] =
        "Host preserved github-*\n"
        "  HostName wildcard.example.test\n"
        "  IdentityFile \"/preserved/wildcard-key\"\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_conflict_rejected_before_publication(
        config, original, sizeof(original) - 1U, &account);
}

TEST(earlier_managed_wildcard_overlap_is_rejected_before_alias_publication) {
    static const char original[] =
        "# >>> gitswitch github-* >>>\n"
        "Host github-*\n"
        "  HostName wildcard.example.test\n"
        "  IdentityFile \"/preserved/managed-wildcard-key\"\n"
        "  IdentitiesOnly yes\n"
        "# <<< gitswitch github-* <<<\n"
        "Host preserved\n"
        "  User alice\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_conflict_rejected_before_publication(
        config, original, sizeof(original) - 1U, &account);
}

TEST(later_managed_wildcard_identity_accumulation_is_rejected_before_publication) {
    static const char original[] =
        BEGIN_MARK "\n"
        "Host " TEST_ALIAS "\n"
        "  HostName github.com\n"
        "  IdentityFile \"/preserved/intended-key\"\n"
        "  IdentitiesOnly yes\n"
        END_MARK "\n"
        "# >>> gitswitch github-* >>>\n"
        "Host github-*\n"
        "  HostName wildcard.example.test\n"
        "  IdentityFile \"/preserved/foreign-key\"\n"
        "  IdentitiesOnly yes\n"
        "# <<< gitswitch github-* <<<\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_conflict_rejected_before_publication(
        config, original, sizeof(original) - 1U, &account);
}

TEST(negated_unmanaged_wildcard_exception_does_not_conflict) {
    static const char original[] =
        "Host * !" TEST_ALIAS "\n"
        "  HostName excluded.example.test\n"
        "  IdentityFile \"/preserved/excluded-key\"\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_config_permitted_without_mutation(
        config, original, sizeof(original) - 1U, &account);
}

TEST(escaped_leading_bang_is_literal_and_wildcard_still_conflicts) {
    static const char original[] =
        "Host \\!" TEST_ALIAS " *\n"
        "  HostName escaped-bang.example.test\n"
        "  IdentityFile \"/preserved/escaped-bang-key\"\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_conflict_rejected_before_publication(
        config, original, sizeof(original) - 1U, &account);
}

TEST(comma_separated_text_is_one_nonmatching_pattern) {
    static const char original[] =
        "Host preserved," TEST_ALIAS "\n"
        "  HostName comma-literal.example.test\n"
        "  IdentityFile \"/preserved/comma-key\"\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_config_permitted_without_mutation(
        config, original, sizeof(original) - 1U, &account);
}

TEST(similar_exact_alias_does_not_conflict) {
    static const char original[] =
        "Host " TEST_ALIAS "-old\n"
        "  HostName old.example.test\n"
        "  IdentityFile \"/preserved/old-key\"\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_config_permitted_without_mutation(
        config, original, sizeof(original) - 1U, &account);
}

TEST(wildcard_target_pattern_conflicting_with_exact_host_is_rejected) {
    static const char original[] =
        "Host github-work\n"
        "  HostName exact.example.test\n"
        "  IdentityFile \"/preserved/exact-key\"\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);
    snprintf(account.ssh_host_alias, sizeof(account.ssh_host_alias),
             "github-*");

    check_alias_conflict_rejected_before_publication(
        config, original, sizeof(original) - 1U, &account);
}

TEST(question_target_pattern_conflicting_with_exact_host_is_rejected) {
    static const char original[] =
        "Host github-work\n"
        "  HostName exact.example.test\n"
        "  IdentityFile \"/preserved/exact-key\"\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);
    snprintf(account.ssh_host_alias, sizeof(account.ssh_host_alias),
             "git?ub-work");

    check_alias_conflict_rejected_before_publication(
        config, original, sizeof(original) - 1U, &account);
}

TEST(case_insensitive_indented_host_equals_directive_is_rejected) {
    static const char original[] =
        "  hOsT=github-*\n"
        "  HostName syntax.example.test\n"
        "  IdentityFile \"/preserved/syntax-key\"\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_conflict_rejected_before_publication(
        config, original, sizeof(original) - 1U, &account);
}

TEST(bare_carriage_return_host_whitespace_is_rejected) {
    static const char original[] =
        " \rHost\rgithub-*\n"
        "  HostName carriage-return.example.test\n"
        "  IdentityFile \"/preserved/carriage-return-key\"\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_conflict_rejected_before_publication(
        config, original, sizeof(original) - 1U, &account);
}

TEST(host_patterns_remain_case_sensitive) {
    static const char original[] =
        "Host GITHUB-*\n"
        "  HostName case.example.test\n"
        "  IdentityFile \"/preserved/case-key\"\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_config_permitted_without_mutation(
        config, original, sizeof(original) - 1U, &account);
}

TEST(matching_host_with_proxy_command_is_permitted) {
    static const char original[] =
        "Host github-*\n"
        "  ProxyCommand false\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_config_permitted_without_mutation(
        config, original, sizeof(original) - 1U, &account);
}

TEST(matching_host_with_harmless_options_is_permitted) {
    static const char original[] =
        "Host *\n"
        "  ServerAliveInterval 30\n"
        "  Compression yes\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_config_permitted_without_mutation(
        config, original, sizeof(original) - 1U, &account);
}

TEST(matching_host_with_certificate_file_is_rejected) {
    static const char original[] =
        "Host github-*\n"
        "  CertificateFile \"/preserved/foreign-cert.pub\"\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_conflict_rejected_before_publication(
        config, original, sizeof(original) - 1U, &account);
}

TEST(matching_host_with_hostname_only_is_rejected) {
    static const char original[] =
        "Host github-*\n"
        "  HostName foreign.example.test\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_conflict_rejected_before_publication(
        config, original, sizeof(original) - 1U, &account);
}

TEST(matching_host_with_identity_file_only_is_rejected) {
    static const char original[] =
        "Host github-*\n"
        "  IdentityFile \"/preserved/foreign-key\"\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_conflict_rejected_before_publication(
        config, original, sizeof(original) - 1U, &account);
}

TEST(matching_host_with_identities_only_is_rejected) {
    static const char original[] =
        "Host github-*\n"
        "  IdentitiesOnly no\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_conflict_rejected_before_publication(
        config, original, sizeof(original) - 1U, &account);
}

TEST(overlong_host_pattern_fails_closed_before_publication) {
    char original[MAX_NAME_LEN * 8U + 64U];
    char pattern[MAX_NAME_LEN * 8U + 1U];
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;
    int needed;

    memset(pattern, 'a', sizeof(pattern) - 1U);
    pattern[sizeof(pattern) - 1U] = '\0';
    needed = snprintf(original, sizeof(original),
                      "Host %s\n  ProxyCommand false\n", pattern);
    CHECK(needed > 0 && (size_t)needed < sizeof(original));
    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original,
                             needed > 0 ? (size_t)needed : 0U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_conflict_rejected_before_publication(
        config, original, needed > 0 ? (size_t)needed : 0U, &account);
}

TEST(include_directive_fails_closed_before_alias_publication) {
    static const char original[] =
        "Include /preserved/external-ssh-config\n"
        "Host preserved\n"
        "  User alice\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_conflict_rejected_before_publication(
        config, original, sizeof(original) - 1U, &account);
}

TEST(match_directive_fails_closed_before_alias_publication) {
    static const char original[] =
        "Match host " TEST_ALIAS "\n"
        "  HostName match.example.test\n"
        "  IdentityFile \"/preserved/match-key\"\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_conflict_rejected_before_publication(
        config, original, sizeof(original) - 1U, &account);
}

TEST(global_routing_options_fail_closed_before_alias_publication) {
    static const char original[] =
        "HostName global.example.test\n"
        "IdentityFile \"/preserved/global-key\"\n"
        "Host preserved\n"
        "  User alice\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    check_alias_conflict_rejected_before_publication(
        config, original, sizeof(original) - 1U, &account);
}

TEST(malformed_nested_and_mismatched_blocks_fail_closed) {
    static const char *const fixtures[] = {
        BEGIN_MARK "\nHost " TEST_ALIAS "\n  IdentityFile /old\n"
        "  IdentitiesOnly yes\n",
        BEGIN_MARK "\nHost wrong-alias\n  IdentityFile /old\n"
        "  IdentitiesOnly yes\n" END_MARK "\n",
        BEGIN_MARK "\nHost " TEST_ALIAS "\n"
        "# >>> gitswitch other >>>\nHost other\n"
        "  IdentityFile /other\n  IdentitiesOnly yes\n"
        "# <<< gitswitch other <<<\n" END_MARK "\n",
        BEGIN_MARK "\nHost " TEST_ALIAS "\n  IdentityFile /old\n"
        "  IdentitiesOnly yes\n# <<< gitswitch other <<<\n",
        BEGIN_MARK "\nHost " TEST_ALIAS "\n  IdentityFile /valid\n"
        "  IdentitiesOnly yes\n" END_MARK "\n"
        BEGIN_MARK "\nHost " TEST_ALIAS "\n  ProxyCommand false\n" END_MARK "\n",
        BEGIN_MARK "\nHost " TEST_ALIAS "\n  HostName bad%h\n"
        "  IdentityFile /old\n  IdentitiesOnly yes\n" END_MARK "\n"
    };

    for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); i++) {
        char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
        struct stat before;
        account_t account;
        size_t fixture_len = strlen(fixtures[i]);
        CHECK_EQ_INT(setup_home(home, config), 0);
        snprintf(key, sizeof(key), "%s/id", home);
        make_account(&account, key);
        CHECK_EQ_INT(write_bytes(config, fixtures[i], fixture_len), 0);
        CHECK_EQ_INT(stat(config, &before), 0);
        CHECK_EQ_INT(ssh_configure_host_alias(&account), -1);
        CHECK_EQ_INT(ssh_remove_host_alias(TEST_ALIAS), -1);
        check_unchanged(config, fixtures[i], fixture_len, &before);
    }
}

TEST(valid_duplicates_collapse_to_one_then_remove_to_zero) {
    static const char original[] =
        "Host user-top\n  User alice\n"
        BEGIN_MARK "\nHost " TEST_ALIAS "\n"
        "  IdentityFile /old path/one\n  IdentitiesOnly yes\n" END_MARK "\n"
        "# >>> gitswitch other >>>\nHost other\n  HostName other.example\n"
        "  IdentityFile \"/other\"\n  IdentitiesOnly yes\n"
        "# <<< gitswitch other <<<\n"
        BEGIN_MARK "\nHost " TEST_ALIAS "\n  HostName github.com\n"
        "  IdentityFile \"/old/two\"\n  IdentitiesOnly yes\n" END_MARK "\n"
        "Host user-tail\n  User bob\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;
    size_t length = 0;
    char *content;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/new key", home);
    make_account(&account, key);
    CHECK_EQ_INT(ssh_configure_host_alias(&account), 0);
    content = read_bytes(config, &length);
    CHECK(content != NULL);
    if (content) {
        CHECK_EQ_INT(count_text(content, BEGIN_MARK), 1);
        CHECK_EQ_INT(count_text(content, END_MARK), 1);
        CHECK_EQ_INT(count_text(content, "# >>> gitswitch other >>>"), 1);
        CHECK(strstr(content, "Host user-top") != NULL);
        CHECK(strstr(content, "Host user-tail") != NULL);
        CHECK(strstr(content, "IdentityFile \"") != NULL);
        free(content);
    }

    CHECK_EQ_INT(ssh_remove_host_alias(TEST_ALIAS), 0);
    content = read_bytes(config, &length);
    CHECK(content != NULL);
    if (content) {
        CHECK_EQ_INT(count_text(content, BEGIN_MARK), 0);
        CHECK_EQ_INT(count_text(content, END_MARK), 0);
        CHECK_EQ_INT(count_text(content, "# >>> gitswitch other >>>"), 1);
        CHECK(strstr(content, "Host user-top") != NULL);
        CHECK(strstr(content, "Host user-tail") != NULL);
        free(content);
    }
}

TEST(crlf_duplicates_collapse_and_preserve_unrelated_bytes) {
    static const char preserved[] =
        "Host user-top\r\n  User alice\r\n"
        "# >>> gitswitch other >>>\r\nHost other\r\n"
        "  HostName other.example\r\n"
        "  IdentityFile \"/other\"\r\n  IdentitiesOnly yes\r\n"
        "# <<< gitswitch other <<<\r\n"
        "Host user-tail\r\n  User bob\r\n";
    static const char original[] =
        "Host user-top\r\n  User alice\r\n"
        BEGIN_MARK "\r\nHost " TEST_ALIAS "\r\n"
        "  HostName stale-one.example\r\n"
        "  IdentityFile \"/stale/one\"\r\n  IdentitiesOnly yes\r\n"
        END_MARK "\r\n"
        "# >>> gitswitch other >>>\r\nHost other\r\n"
        "  HostName other.example\r\n"
        "  IdentityFile \"/other\"\r\n  IdentitiesOnly yes\r\n"
        "# <<< gitswitch other <<<\r\n"
        BEGIN_MARK "\r\nHost " TEST_ALIAS "\r\n"
        "  HostName stale-two.example\r\n"
        "  IdentityFile \"/stale/two\"\r\n  IdentitiesOnly yes\r\n"
        END_MARK "\r\n"
        "Host user-tail\r\n  User bob\r\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    char output[32768];
    account_t account;
    run_opts_t opts;
    run_result_t result;
    size_t length = 0;
    char *content;

    if (!command_exists("ssh")) {
        TS_SKIP("openssh", "ssh unavailable in trusted PATH");
    }
    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/new key", home);
    make_account(&account, key);
    CHECK_EQ_INT(ssh_configure_host_alias(&account), 0);

    content = read_bytes(config, &length);
    CHECK(content != NULL);
    if (content) {
        CHECK(length > sizeof(preserved) - 1U);
        CHECK(length <= sizeof(preserved) - 1U ||
              memcmp(content, preserved, sizeof(preserved) - 1U) == 0);
        CHECK_EQ_INT(count_text(content, BEGIN_MARK), 1);
        CHECK_EQ_INT(count_text(content, END_MARK), 1);
        CHECK(strstr(content, "stale-one.example") == NULL);
        CHECK(strstr(content, "stale-two.example") == NULL);
        free(content);
    }

    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.out = output;
    opts.out_size = sizeof(output);
    opts.merge_stderr = true;
    {
        const char *const argv[] = {
            "ssh", "-G", "-F", config, TEST_ALIAS, NULL
        };
        CHECK_EQ_INT(run_argv(argv, &opts, &result), 0);
    }
    CHECK(!result.out_truncated);
    CHECK(output_has_value(output, "hostname", TEST_HOSTNAME));
    CHECK(output_has_value(output, "identityfile", key));
}

TEST(crlf_remove_preserves_all_unmanaged_bytes) {
    static const char before[] = "Host before\r\n  User alice\r\n";
    static const char after[] = "Host after\r\n  User bob\r\n";
    static const char original[] =
        "Host before\r\n  User alice\r\n"
        BEGIN_MARK "\r\nHost " TEST_ALIAS "\r\n"
        "  HostName github.com\r\n"
        "  IdentityFile \"/stale/key\"\r\n  IdentitiesOnly yes\r\n"
        END_MARK "\r\n"
        "Host after\r\n  User bob\r\n";
    char home[96], config[MAX_PATH_LEN];
    char expected[sizeof(before) + sizeof(after)];
    size_t expected_len;
    size_t length = 0;
    char *content;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    CHECK_EQ_INT(ssh_remove_host_alias(TEST_ALIAS), 0);
    expected_len = (sizeof(before) - 1U) + (sizeof(after) - 1U);
    memcpy(expected, before, sizeof(before) - 1U);
    memcpy(expected + sizeof(before) - 1U, after, sizeof(after) - 1U);

    content = read_bytes(config, &length);
    CHECK(content != NULL);
    if (content) {
        CHECK_EQ_INT(length, expected_len);
        CHECK(length != expected_len ||
              memcmp(content, expected, expected_len) == 0);
        CHECK_EQ_INT(count_text(content, BEGIN_MARK), 0);
        CHECK_EQ_INT(count_text(content, END_MARK), 0);
        free(content);
    }
}

TEST(byte_identical_config_skips_all_write_and_sync_work) {
    static const mode_t safe_modes[] = {0600, 0644};

    for (size_t i = 0; i < sizeof(safe_modes) / sizeof(safe_modes[0]); i++) {
        identical_config_fixture_t fixture;
        struct stat after;
        ssh_config_publication_state_t publication;
        ssh_config_commit_hook_fn previous_commit;
        ssh_dirsync_fn previous_sync;
        int rc;

        if (setup_identical_config_fixture(&fixture, safe_modes[i]) != 0) {
            CHECK(false);
            continue;
        }
        CHECK_EQ_INT(fixture.config_identity.st_uid, getuid());
        CHECK_EQ_INT(fixture.config_identity.st_mode & 0777, safe_modes[i]);

        g_identical_commit_hook_calls = 0;
        g_dirsync_calls = 0;
        reset_dirsync_observations(&fixture.ssh_identity, false);
        previous_commit = ssh_manager_set_config_commit_hook_fn(
            fail_identical_config_commit);
        previous_sync = ssh_manager_set_dirsync_fn(observe_dirsync);
        rc = ssh_configure_host_alias_result(&fixture.account, &publication);
        ssh_manager_set_dirsync_fn(previous_sync);
        ssh_manager_set_config_commit_hook_fn(previous_commit);

        CHECK_EQ_INT(rc, 0);
        CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_UNCHANGED);
        CHECK_EQ_INT(g_identical_commit_hook_calls, 0);
        /* AR-12 M6 / AR-13 L32: exactly one directory sync re-proves durability
         * and it targets the ~/.ssh directory — the old count-only assertion
         * would pass even if the wrong directory were synced. No write work
         * happens (identity, mtime, and bytes are untouched). */
        CHECK_EQ_INT((int)g_dirsync_observation_count, 1);
        CHECK(ts_same_identity(&g_dirsync_observations[0],
                               &fixture.ssh_identity));
        CHECK_EQ_INT(stat(fixture.config, &after), 0);
        CHECK(ts_same_identity(&fixture.config_identity, &after));
        CHECK(same_mtime(&fixture.config_identity, &after));
        CHECK_EQ_INT(after.st_mode & 0777, safe_modes[i]);
        CHECK_EQ_INT(after.st_uid, getuid());
        check_exact_file_bytes(fixture.config, fixture.content,
                               fixture.content_len);
        check_identical_fixture_clean(&fixture);
    }

    /* AR-12 M6 regression: a failing directory sync on the no-op path must
     * report DURABILITY_UNCERTAIN instead of converting a prior uncertain
     * rename into silent success. */
    {
        identical_config_fixture_t fixture;
        ssh_config_publication_state_t publication;
        ssh_config_commit_hook_fn previous_commit;
        ssh_dirsync_fn previous_sync;
        int rc;

        if (setup_identical_config_fixture(&fixture, 0600) != 0) {
            CHECK(false);
            return;
        }
        g_identical_commit_hook_calls = 0;
        g_dirsync_calls = 0;
        previous_commit = ssh_manager_set_config_commit_hook_fn(
            fail_identical_config_commit);
        previous_sync = ssh_manager_set_dirsync_fn(fail_dirsync);
        clear_error();
        rc = ssh_configure_host_alias_result(&fixture.account, &publication);
        ssh_manager_set_dirsync_fn(previous_sync);
        ssh_manager_set_config_commit_hook_fn(previous_commit);

        CHECK_EQ_INT(rc, -1);
        CHECK_EQ_INT(publication,
                     SSH_CONFIG_PUBLICATION_DURABILITY_UNCERTAIN);
        CHECK_EQ_INT(g_dirsync_calls, 1);
        CHECK(strstr(get_last_error()->message,
                     "durability remains uncertain") != NULL);
        check_exact_file_bytes(fixture.config, fixture.content,
                               fixture.content_len);
        check_identical_fixture_clean(&fixture);
    }
}

TEST(byte_identical_safe_config_rechecks_mode_before_noop) {
    identical_config_fixture_t fixture;
    struct stat raced;
    struct stat normalized;
    error_context_t failure;
    ssh_config_publication_state_t publication;
    ssh_metadata_test_hook_fn previous_metadata;
    ssh_config_commit_hook_fn previous_commit;
    ssh_dirsync_fn previous_sync;
    int rc;

    if (setup_identical_config_fixture(&fixture, 0600) != 0) {
        CHECK(false);
        return;
    }
    CHECK((size_t)snprintf(g_unchanged_recheck_config,
                           sizeof(g_unchanged_recheck_config), "%s",
                           fixture.config) <
          sizeof(g_unchanged_recheck_config));
    g_unchanged_recheck_hook_calls = 0;
    g_unchanged_recheck_chmod_succeeded = false;
    g_identical_commit_hook_calls = 0;
    g_dirsync_calls = 0;
    previous_metadata = ssh_manager_set_metadata_test_hook_fn(
        make_config_writable_before_unchanged_recheck);
    previous_commit = ssh_manager_set_config_commit_hook_fn(
        fail_identical_config_commit);
    previous_sync = ssh_manager_set_dirsync_fn(fail_dirsync);
    clear_error();
    rc = ssh_configure_host_alias_result(&fixture.account, &publication);
    failure = *get_last_error();
    ssh_manager_set_dirsync_fn(previous_sync);
    ssh_manager_set_config_commit_hook_fn(previous_commit);
    ssh_manager_set_metadata_test_hook_fn(previous_metadata);
    g_unchanged_recheck_config[0] = '\0';

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_PREINSTALL_FAILED);
    CHECK_EQ_INT(failure.code, ERR_FILE_IO);
    CHECK(strstr(failure.message, "SSH config changed") != NULL);
    CHECK_EQ_INT(g_unchanged_recheck_hook_calls, 1);
    CHECK(g_unchanged_recheck_chmod_succeeded);
    CHECK_EQ_INT(g_identical_commit_hook_calls, 0);
    CHECK_EQ_INT(g_dirsync_calls, 0);
    CHECK_EQ_INT(lstat(fixture.config, &raced), 0);
    CHECK(ts_same_identity(&fixture.config_identity, &raced));
    CHECK(same_mtime(&fixture.config_identity, &raced));
    CHECK_EQ_INT(raced.st_mode & 0777, 0666);
    check_exact_file_bytes(fixture.config, fixture.content,
                           fixture.content_len);
    CHECK_EQ_INT(count_temps_in(fixture.ssh_dir), 0);
    CHECK_EQ_INT(test_open_fd_count(), fixture.open_fds);

    reset_dirsync_observations(&fixture.home_identity, false);
    previous_sync = ssh_manager_set_dirsync_fn(observe_dirsync);
    clear_error();
    rc = ssh_configure_host_alias_result(&fixture.account, &publication);
    ssh_manager_set_dirsync_fn(previous_sync);
    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_COMMITTED);
    CHECK_EQ_INT(g_dirsync_observation_count, 1);
    CHECK_EQ_INT(lstat(fixture.config, &normalized), 0);
    CHECK(!ts_same_identity(&fixture.config_identity, &normalized));
    CHECK_EQ_INT(normalized.st_uid, getuid());
    CHECK_EQ_INT(normalized.st_mode & 0777, 0600);
    CHECK_EQ_INT(normalized.st_nlink, 1);
    check_exact_file_bytes(fixture.config, fixture.content,
                           fixture.content_len);
    check_identical_fixture_clean(&fixture);
}

TEST(byte_identical_safe_config_rebinds_final_public_directory) {
    static const char replacement[] =
        "Host replacement\n  User untouched\n";
    identical_config_fixture_t fixture;
    char moved_config[MAX_PATH_LEN];
    struct stat public_after;
    struct stat moved_after;
    error_context_t failure;
    ssh_config_publication_state_t publication;
    ssh_metadata_test_hook_fn previous_metadata;
    ssh_config_commit_hook_fn previous_commit;
    ssh_dirsync_fn previous_sync;
    int rc;

    if (setup_identical_config_fixture(&fixture, 0600) != 0) {
        CHECK(false);
        return;
    }
    CHECK((size_t)snprintf(g_public_ssh_dir, sizeof(g_public_ssh_dir), "%s",
                           fixture.ssh_dir) < sizeof(g_public_ssh_dir));
    CHECK((size_t)snprintf(g_moved_ssh_dir, sizeof(g_moved_ssh_dir),
                           "%s/.ssh.noop-pinned", fixture.home) <
          sizeof(g_moved_ssh_dir));
    CHECK((size_t)snprintf(moved_config, sizeof(moved_config), "%s/config",
                           g_moved_ssh_dir) < sizeof(moved_config));
    g_unchanged_final_recheck_hook_calls = 0;
    g_unchanged_final_recheck_swap_succeeded = false;
    g_identical_commit_hook_calls = 0;
    g_dirsync_calls = 0;
    previous_metadata = ssh_manager_set_metadata_test_hook_fn(
        swap_ssh_directory_before_unchanged_final_recheck);
    previous_commit = ssh_manager_set_config_commit_hook_fn(
        fail_identical_config_commit);
    previous_sync = ssh_manager_set_dirsync_fn(fail_dirsync);
    clear_error();
    rc = ssh_configure_host_alias_result(&fixture.account, &publication);
    failure = *get_last_error();
    ssh_manager_set_dirsync_fn(previous_sync);
    ssh_manager_set_config_commit_hook_fn(previous_commit);
    ssh_manager_set_metadata_test_hook_fn(previous_metadata);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_PREINSTALL_FAILED);
    CHECK_EQ_INT(failure.code, ERR_FILE_IO);
    CHECK(strstr(failure.message, "SSH config directory changed") != NULL);
    CHECK_EQ_INT(g_unchanged_final_recheck_hook_calls, 1);
    CHECK(g_unchanged_final_recheck_swap_succeeded);
    CHECK_EQ_INT(g_identical_commit_hook_calls, 0);
    CHECK_EQ_INT(g_dirsync_calls, 0);
    CHECK_EQ_INT(lstat(fixture.config, &public_after), 0);
    CHECK_EQ_INT(lstat(moved_config, &moved_after), 0);
    CHECK(!ts_same_identity(&fixture.config_identity, &public_after));
    CHECK(ts_same_identity(&fixture.config_identity, &moved_after));
    CHECK_EQ_INT(public_after.st_uid, getuid());
    CHECK_EQ_INT(public_after.st_mode & 0777, 0600);
    CHECK_EQ_INT(moved_after.st_uid, getuid());
    CHECK_EQ_INT(moved_after.st_mode & 0777, 0600);
    check_exact_file_bytes(fixture.config, replacement,
                           sizeof(replacement) - 1U);
    check_exact_file_bytes(moved_config, fixture.content,
                           fixture.content_len);
    CHECK_EQ_INT(count_temps_in(g_public_ssh_dir), 0);
    CHECK_EQ_INT(count_temps_in(g_moved_ssh_dir), 0);
    CHECK_EQ_INT(test_open_fd_count(), fixture.open_fds);
    g_public_ssh_dir[0] = '\0';
    g_moved_ssh_dir[0] = '\0';
    check_identical_fixture_clean(&fixture);
}

TEST(byte_identical_safe_hardlink_remains_unchanged) {
    identical_config_fixture_t fixture;
    char witness[MAX_PATH_LEN];
    struct stat before;
    struct stat witness_before;
    struct stat after;
    struct stat witness_after;
    ssh_config_publication_state_t publication;
    ssh_config_commit_hook_fn previous_commit;
    ssh_dirsync_fn previous_sync;
    int rc;

    if (setup_identical_config_fixture(&fixture, 0600) != 0) {
        CHECK(false);
        return;
    }
    if ((size_t)snprintf(witness, sizeof(witness), "%s/config.safe-witness",
                         fixture.ssh_dir) >= sizeof(witness) ||
        link(fixture.config, witness) != 0 ||
        lstat(fixture.config, &before) != 0 ||
        lstat(witness, &witness_before) != 0) {
        CHECK(false);
        check_identical_fixture_clean(&fixture);
        return;
    }
    CHECK(ts_same_identity(&before, &witness_before));
    CHECK_EQ_INT(before.st_nlink, 2);
    CHECK_EQ_INT(before.st_mode & 0777, 0600);

    g_identical_commit_hook_calls = 0;
    g_dirsync_calls = 0;
    reset_dirsync_observations(&fixture.ssh_identity, false);
    previous_commit = ssh_manager_set_config_commit_hook_fn(
        fail_identical_config_commit);
    previous_sync = ssh_manager_set_dirsync_fn(observe_dirsync);
    rc = ssh_configure_host_alias_result(&fixture.account, &publication);
    ssh_manager_set_dirsync_fn(previous_sync);
    ssh_manager_set_config_commit_hook_fn(previous_commit);

    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_UNCHANGED);
    CHECK_EQ_INT(g_identical_commit_hook_calls, 0);
    /* AR-12 M6 / AR-13 L32: one durability-proving sync, targeting ~/.ssh; no
     * write work. Verifying the synced directory catches a wrong-dir sync. */
    CHECK_EQ_INT((int)g_dirsync_observation_count, 1);
    CHECK(ts_same_identity(&g_dirsync_observations[0], &fixture.ssh_identity));
    CHECK_EQ_INT(lstat(fixture.config, &after), 0);
    CHECK_EQ_INT(lstat(witness, &witness_after), 0);
    CHECK(ts_same_identity(&before, &after));
    CHECK(ts_same_identity(&before, &witness_after));
    CHECK(same_mtime(&before, &after));
    CHECK_EQ_INT(after.st_nlink, 2);
    CHECK_EQ_INT(after.st_mode & 0777, 0600);
    check_exact_file_bytes(fixture.config, fixture.content,
                           fixture.content_len);
    check_exact_file_bytes(witness, fixture.content, fixture.content_len);
    check_identical_fixture_clean(&fixture);
}

TEST(byte_identical_writable_mode_matrix_is_atomically_normalized) {
    static const mode_t writable_modes[] = {0620, 0602, 0666};

    for (size_t i = 0;
         i < sizeof(writable_modes) / sizeof(writable_modes[0]); i++) {
        identical_config_fixture_t fixture;
        struct stat after;
        ssh_config_publication_state_t publication;
        ssh_dirsync_fn previous_sync;
        int rc;

        if (setup_identical_config_fixture(&fixture, writable_modes[i]) != 0) {
            CHECK(false);
            continue;
        }
        CHECK_EQ_INT(fixture.config_identity.st_uid, getuid());
        CHECK_EQ_INT(fixture.config_identity.st_mode & 0777,
                     writable_modes[i]);

        reset_dirsync_observations(&fixture.home_identity, false);
        previous_sync = ssh_manager_set_dirsync_fn(observe_dirsync);
        rc = ssh_configure_host_alias_result(&fixture.account, &publication);
        ssh_manager_set_dirsync_fn(previous_sync);

        CHECK_EQ_INT(rc, 0);
        CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_COMMITTED);
        CHECK_EQ_INT(g_dirsync_observation_count, 1);
        if (g_dirsync_observation_count == 1) {
            CHECK(ts_same_identity(&g_dirsync_observations[0],
                                   &fixture.ssh_identity));
            CHECK(!ts_same_identity(&g_dirsync_observations[0],
                                    &fixture.home_identity));
        }
        CHECK_EQ_INT(lstat(fixture.config, &after), 0);
        CHECK(S_ISREG(after.st_mode));
        CHECK(!ts_same_identity(&fixture.config_identity, &after));
        CHECK_EQ_INT(after.st_uid, getuid());
        CHECK_EQ_INT(after.st_mode & 0777, 0600);
        CHECK_EQ_INT(after.st_nlink, 1);
        check_exact_file_bytes(fixture.config, fixture.content,
                               fixture.content_len);
        check_identical_fixture_clean(&fixture);
    }
}

TEST(byte_identical_writable_hardlink_is_replaced_not_chmodded) {
    identical_config_fixture_t fixture;
    char witness[MAX_PATH_LEN];
    struct stat before;
    struct stat witness_before;
    struct stat after;
    struct stat witness_after;
    ssh_config_publication_state_t publication;
    ssh_dirsync_fn previous_sync;
    int rc;

    if (setup_identical_config_fixture(&fixture, 0666) != 0) {
        CHECK(false);
        return;
    }
    if ((size_t)snprintf(witness, sizeof(witness), "%s/config.mode-witness",
                         fixture.ssh_dir) >= sizeof(witness) ||
        link(fixture.config, witness) != 0 ||
        lstat(fixture.config, &before) != 0 ||
        lstat(witness, &witness_before) != 0) {
        CHECK(false);
        check_identical_fixture_clean(&fixture);
        return;
    }
    CHECK(ts_same_identity(&before, &witness_before));
    CHECK(before.st_nlink >= 2);
    CHECK_EQ_INT(before.st_mode & 0777, 0666);

    reset_dirsync_observations(&fixture.home_identity, false);
    previous_sync = ssh_manager_set_dirsync_fn(observe_dirsync);
    rc = ssh_configure_host_alias_result(&fixture.account, &publication);
    ssh_manager_set_dirsync_fn(previous_sync);

    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_COMMITTED);
    CHECK_EQ_INT(g_dirsync_observation_count, 1);
    if (g_dirsync_observation_count == 1) {
        CHECK(ts_same_identity(&g_dirsync_observations[0],
                               &fixture.ssh_identity));
        CHECK(!ts_same_identity(&g_dirsync_observations[0],
                                &fixture.home_identity));
    }
    CHECK_EQ_INT(lstat(fixture.config, &after), 0);
    CHECK_EQ_INT(lstat(witness, &witness_after), 0);
    CHECK(S_ISREG(after.st_mode));
    CHECK(!ts_same_identity(&before, &after));
    CHECK_EQ_INT(after.st_uid, getuid());
    CHECK_EQ_INT(after.st_mode & 0777, 0600);
    CHECK_EQ_INT(after.st_nlink, 1);
    CHECK(ts_same_identity(&before, &witness_after));
    CHECK_EQ_INT(witness_after.st_mode & 0777, 0666);
    check_exact_file_bytes(fixture.config, fixture.content,
                           fixture.content_len);
    check_exact_file_bytes(witness, fixture.content, fixture.content_len);
    check_identical_fixture_clean(&fixture);
}

TEST(byte_identical_writable_preinstall_failure_preserves_original) {
    identical_config_fixture_t fixture;
    struct stat after;
    error_context_t failure;
    ssh_config_publication_state_t publication;
    ssh_config_commit_hook_fn previous_commit;
    ssh_dirsync_fn previous_sync;
    int rc;

    if (setup_identical_config_fixture(&fixture, 0666) != 0) {
        CHECK(false);
        return;
    }
    g_identical_commit_hook_calls = 0;
    reset_dirsync_observations(&fixture.home_identity, false);
    previous_commit = ssh_manager_set_config_commit_hook_fn(
        fail_identical_config_commit);
    previous_sync = ssh_manager_set_dirsync_fn(observe_dirsync);
    clear_error();
    rc = ssh_configure_host_alias_result(&fixture.account, &publication);
    failure = *get_last_error();
    ssh_manager_set_dirsync_fn(previous_sync);
    ssh_manager_set_config_commit_hook_fn(previous_commit);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_PREINSTALL_FAILED);
    CHECK_EQ_INT(failure.code, ERR_FILE_IO);
    CHECK_EQ_INT(g_identical_commit_hook_calls, 1);
    CHECK_EQ_INT(g_dirsync_observation_count, 0);
    CHECK_EQ_INT(lstat(fixture.config, &after), 0);
    CHECK(ts_same_identity(&fixture.config_identity, &after));
    CHECK(same_mtime(&fixture.config_identity, &after));
    CHECK_EQ_INT(after.st_mode & 0777, 0666);
    check_exact_file_bytes(fixture.config, fixture.content,
                           fixture.content_len);
    check_identical_fixture_clean(&fixture);
}

TEST(byte_identical_writable_postrename_failure_reports_installed) {
    identical_config_fixture_t fixture;
    struct stat after;
    error_context_t failure;
    ssh_config_publication_state_t publication;
    ssh_config_postrename_hook_fn previous_postrename;
    ssh_dirsync_fn previous_sync;
    int rc;

    if (setup_identical_config_fixture(&fixture, 0666) != 0) {
        CHECK(false);
        return;
    }
    g_identical_postrename_hook_calls = 0;
    reset_dirsync_observations(&fixture.home_identity, false);
    previous_postrename = ssh_manager_set_config_postrename_hook_fn(
        fail_identical_postrename_verification);
    previous_sync = ssh_manager_set_dirsync_fn(observe_dirsync);
    clear_error();
    rc = ssh_configure_host_alias_result(&fixture.account, &publication);
    failure = *get_last_error();
    ssh_manager_set_dirsync_fn(previous_sync);
    ssh_manager_set_config_postrename_hook_fn(previous_postrename);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(publication,
                 SSH_CONFIG_PUBLICATION_INSTALLED_UNVERIFIED);
    CHECK_EQ_INT(failure.code, ERR_FILE_IO);
    CHECK_EQ_INT(g_identical_postrename_hook_calls, 1);
    CHECK_EQ_INT(g_dirsync_observation_count, 0);
    CHECK_EQ_INT(lstat(fixture.config, &after), 0);
    CHECK(S_ISREG(after.st_mode));
    CHECK(!ts_same_identity(&fixture.config_identity, &after));
    CHECK_EQ_INT(after.st_uid, getuid());
    CHECK_EQ_INT(after.st_mode & 0777, 0600);
    CHECK_EQ_INT(after.st_nlink, 1);
    check_exact_file_bytes(fixture.config, fixture.content,
                           fixture.content_len);
    check_identical_fixture_clean(&fixture);
}

TEST(byte_identical_writable_dirsync_failure_reports_uncertain) {
    identical_config_fixture_t fixture;
    struct stat after;
    error_context_t failure;
    ssh_config_publication_state_t publication;
    ssh_dirsync_fn previous_sync;
    int rc;

    if (setup_identical_config_fixture(&fixture, 0666) != 0) {
        CHECK(false);
        return;
    }
    reset_dirsync_observations(&fixture.ssh_identity, true);
    previous_sync = ssh_manager_set_dirsync_fn(observe_dirsync);
    clear_error();
    rc = ssh_configure_host_alias_result(&fixture.account, &publication);
    failure = *get_last_error();
    ssh_manager_set_dirsync_fn(previous_sync);

    CHECK_EQ_INT(rc, -1);
    CHECK_EQ_INT(publication,
                 SSH_CONFIG_PUBLICATION_DURABILITY_UNCERTAIN);
    CHECK_EQ_INT(failure.code, ERR_FILE_IO);
    CHECK_EQ_INT(failure.system_errno, EIO);
    CHECK_EQ_INT(g_dirsync_observation_count, 1);
    if (g_dirsync_observation_count == 1) {
        CHECK(ts_same_identity(&g_dirsync_observations[0],
                               &fixture.ssh_identity));
        CHECK(!ts_same_identity(&g_dirsync_observations[0],
                                &fixture.home_identity));
    }
    CHECK_EQ_INT(lstat(fixture.config, &after), 0);
    CHECK(S_ISREG(after.st_mode));
    CHECK(!ts_same_identity(&fixture.config_identity, &after));
    CHECK_EQ_INT(after.st_uid, getuid());
    CHECK_EQ_INT(after.st_mode & 0777, 0600);
    CHECK_EQ_INT(after.st_nlink, 1);
    check_exact_file_bytes(fixture.config, fixture.content,
                           fixture.content_len);
    check_identical_fixture_clean(&fixture);
}

TEST(first_ssh_directory_syncs_home_before_child) {
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    char ssh_dir[MAX_PATH_LEN];
    account_t account;
    struct stat home_identity;
    struct stat ssh_identity;
    struct stat config_identity;
    ssh_config_publication_state_t publication;
    ssh_dirsync_fn previous;
    size_t length = 0;
    char *content;
    int before;

    CHECK_EQ_INT(setup_home_without_ssh(home, config), 0);
    CHECK_EQ_INT(stat(home, &home_identity), 0);
    CHECK((size_t)snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home) <
          sizeof(ssh_dir));
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    before = test_open_fd_count();
    reset_dirsync_observations(&home_identity, false);
    previous = ssh_manager_set_dirsync_fn(observe_dirsync);
    CHECK_EQ_INT(ssh_configure_host_alias_result(&account, &publication), 0);
    ssh_manager_set_dirsync_fn(previous);

    CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_COMMITTED);
    CHECK_EQ_INT(g_dirsync_observation_count, 2);
    CHECK(ts_same_identity(&g_dirsync_observations[0], &home_identity));
    CHECK_EQ_INT(lstat(ssh_dir, &ssh_identity), 0);
    CHECK(S_ISDIR(ssh_identity.st_mode));
    CHECK_EQ_INT(ssh_identity.st_uid, getuid());
    CHECK_EQ_INT(ssh_identity.st_mode & 0777, 0700);
    CHECK(ts_same_identity(&g_dirsync_observations[1], &ssh_identity));
    CHECK_EQ_INT(lstat(config, &config_identity), 0);
    CHECK(S_ISREG(config_identity.st_mode));
    CHECK_EQ_INT(config_identity.st_mode & 0777, 0600);
    content = read_bytes(config, &length);
    CHECK(content != NULL);
    if (content) {
        CHECK_EQ_INT(count_text(content, BEGIN_MARK), 1);
        CHECK_EQ_INT(count_text(content, END_MARK), 1);
        free(content);
    }
    CHECK_EQ_INT(count_temps_in(ssh_dir), 0);
    CHECK_EQ_INT(test_open_fd_count(), before);
}

TEST(first_ssh_directory_home_sync_failure_is_preinstall_and_retryable) {
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    char ssh_dir[MAX_PATH_LEN], lock_path[MAX_PATH_LEN];
    account_t account;
    struct stat home_identity;
    struct stat ssh_identity;
    error_context_t failure;
    ssh_config_publication_state_t publication;
    ssh_dirsync_fn previous;
    size_t length = 0;
    char *content;
    int before;

    CHECK_EQ_INT(setup_home_without_ssh(home, config), 0);
    CHECK_EQ_INT(stat(home, &home_identity), 0);
    CHECK((size_t)snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home) <
          sizeof(ssh_dir));
    CHECK((size_t)snprintf(lock_path, sizeof(lock_path),
                           "%s/.gitswitch-config.lock", ssh_dir) <
          sizeof(lock_path));
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    before = test_open_fd_count();
    reset_dirsync_observations(&home_identity, true);
    previous = ssh_manager_set_dirsync_fn(observe_dirsync);
    clear_error();
    CHECK_EQ_INT(ssh_configure_host_alias_result(&account, &publication), -1);
    failure = *get_last_error();
    ssh_manager_set_dirsync_fn(previous);

    CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_PREINSTALL_FAILED);
    CHECK_EQ_INT(failure.code, ERR_FILE_IO);
    CHECK_EQ_INT(failure.system_errno, EIO);
    CHECK(strstr(failure.message, "HOME") != NULL);
    CHECK(strstr(failure.message, "uncertain") != NULL);
    CHECK_EQ_INT(g_dirsync_observation_count, 1);
    CHECK(ts_same_identity(&g_dirsync_observations[0], &home_identity));
    CHECK_EQ_INT(lstat(ssh_dir, &ssh_identity), 0);
    CHECK(S_ISDIR(ssh_identity.st_mode));
    CHECK_EQ_INT(ssh_identity.st_uid, getuid());
    CHECK_EQ_INT(ssh_identity.st_mode & 0777, 0700);
    errno = 0;
    CHECK(access(config, F_OK) != 0 && errno == ENOENT);
    errno = 0;
    CHECK(access(lock_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT(count_temps_in(ssh_dir), 0);
    CHECK_EQ_INT(test_open_fd_count(), before);

    /* The retained directory from the failed attempt is not proof that its
     * HOME entry became durable. A retry creating the first config must
     * re-establish the parent sync before publishing inside the child. */
    reset_dirsync_observations(&home_identity, false);
    previous = ssh_manager_set_dirsync_fn(observe_dirsync);
    clear_error();
    CHECK_EQ_INT(ssh_configure_host_alias_result(&account, &publication), 0);
    ssh_manager_set_dirsync_fn(previous);
    CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_COMMITTED);
    CHECK_EQ_INT(g_dirsync_observation_count, 2);
    CHECK(ts_same_identity(&g_dirsync_observations[0], &home_identity));
    CHECK(ts_same_identity(&g_dirsync_observations[1], &ssh_identity));
    content = read_bytes(config, &length);
    CHECK(content != NULL);
    if (content) {
        CHECK_EQ_INT(count_text(content, BEGIN_MARK), 1);
        free(content);
    }
    CHECK_EQ_INT(count_temps_in(ssh_dir), 0);
    CHECK_EQ_INT(test_open_fd_count(), before);
}

TEST(existing_ssh_directory_syncs_only_child) {
    static const char original[] = "Host existing\n  User preserved\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    char ssh_dir[MAX_PATH_LEN];
    account_t account;
    struct stat home_identity;
    struct stat ssh_identity;
    ssh_config_publication_state_t publication;
    ssh_dirsync_fn previous;
    size_t length = 0;
    char *content;
    int before;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    CHECK_EQ_INT(stat(home, &home_identity), 0);
    CHECK((size_t)snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home) <
          sizeof(ssh_dir));
    CHECK_EQ_INT(stat(ssh_dir, &ssh_identity), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    before = test_open_fd_count();
    reset_dirsync_observations(&home_identity, false);
    previous = ssh_manager_set_dirsync_fn(observe_dirsync);
    CHECK_EQ_INT(ssh_configure_host_alias_result(&account, &publication), 0);
    ssh_manager_set_dirsync_fn(previous);

    CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_COMMITTED);
    CHECK_EQ_INT(g_dirsync_observation_count, 1);
    CHECK(ts_same_identity(&g_dirsync_observations[0], &ssh_identity));
    CHECK(!ts_same_identity(&g_dirsync_observations[0], &home_identity));
    content = read_bytes(config, &length);
    CHECK(content != NULL);
    if (content) {
        CHECK(strstr(content, "Host existing\n") != NULL);
        CHECK_EQ_INT(count_text(content, BEGIN_MARK), 1);
        free(content);
    }
    CHECK_EQ_INT(count_temps_in(ssh_dir), 0);
    CHECK_EQ_INT(test_open_fd_count(), before);
}

TEST(configless_existing_ssh_syncs_parent_before_first_publication) {
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    char ssh_dir[MAX_PATH_LEN];
    account_t account;
    struct stat home_identity;
    struct stat ssh_identity;
    ssh_config_publication_state_t publication;
    ssh_dirsync_fn previous;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(stat(home, &home_identity), 0);
    CHECK((size_t)snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home) <
          sizeof(ssh_dir));
    CHECK_EQ_INT(stat(ssh_dir, &ssh_identity), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);

    reset_dirsync_observations(&home_identity, false);
    previous = ssh_manager_set_dirsync_fn(observe_dirsync);
    CHECK_EQ_INT(ssh_configure_host_alias_result(&account, &publication), 0);
    ssh_manager_set_dirsync_fn(previous);

    CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_COMMITTED);
    CHECK_EQ_INT(g_dirsync_observation_count, 2);
    CHECK(ts_same_identity(&g_dirsync_observations[0], &home_identity));
    CHECK(ts_same_identity(&g_dirsync_observations[1], &ssh_identity));
    CHECK_EQ_INT(count_temps_in(ssh_dir), 0);
}

TEST(symlinked_home_first_publication_syncs_resolved_parent) {
    char root[96];
    char real_home[MAX_PATH_LEN], public_home[MAX_PATH_LEN];
    char config[MAX_PATH_LEN], key[MAX_PATH_LEN], ssh_dir[MAX_PATH_LEN];
    account_t account;
    struct stat home_identity;
    struct stat ssh_identity;
    ssh_config_publication_state_t publication;
    ssh_dirsync_fn previous;
    int before;

    CHECK_EQ_INT(setup_symlinked_home(root, real_home, public_home, config), 0);
    CHECK_EQ_INT(stat(real_home, &home_identity), 0);
    CHECK((size_t)snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", real_home) <
          sizeof(ssh_dir));
    snprintf(key, sizeof(key), "%s/id", root);
    make_account(&account, key);

    before = test_open_fd_count();
    reset_dirsync_observations(&home_identity, false);
    previous = ssh_manager_set_dirsync_fn(observe_dirsync);
    CHECK_EQ_INT(ssh_configure_host_alias_result(&account, &publication), 0);
    ssh_manager_set_dirsync_fn(previous);

    CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_COMMITTED);
    CHECK_EQ_INT(g_dirsync_observation_count, 2);
    CHECK(ts_same_identity(&g_dirsync_observations[0], &home_identity));
    CHECK_EQ_INT(stat(ssh_dir, &ssh_identity), 0);
    CHECK(ts_same_identity(&g_dirsync_observations[1], &ssh_identity));
    CHECK_EQ_INT(access(config, F_OK), 0);
    CHECK_EQ_INT(count_temps_in(ssh_dir), 0);
    CHECK_EQ_INT(test_open_fd_count(), before);
}

TEST(descriptor_relative_first_creation_ignores_home_retarget) {
    char root[96];
    char real_home[MAX_PATH_LEN], public_home[MAX_PATH_LEN];
    char config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    char original_ssh[MAX_PATH_LEN], original_config[MAX_PATH_LEN];
    char replacement_ssh[MAX_PATH_LEN];
    account_t account;
    struct stat home_identity;
    struct stat ssh_identity;
    error_context_t failure;
    ssh_config_publication_state_t publication;
    ssh_metadata_test_hook_fn previous_metadata;
    ssh_dirsync_fn previous_sync;
    int before;

    CHECK_EQ_INT(setup_symlinked_home(root, real_home, public_home, config), 0);
    CHECK((size_t)snprintf(g_replacement_home,
                           sizeof(g_replacement_home), "%s/replacement",
                           root) < sizeof(g_replacement_home));
    CHECK_EQ_INT(mkdir(g_replacement_home, 0700), 0);
    CHECK_EQ_INT(stat(real_home, &home_identity), 0);
    CHECK((size_t)snprintf(g_public_home_link,
                           sizeof(g_public_home_link), "%s", public_home) <
          sizeof(g_public_home_link));
    CHECK((size_t)snprintf(original_ssh, sizeof(original_ssh), "%s/.ssh",
                           real_home) < sizeof(original_ssh));
    CHECK((size_t)snprintf(original_config, sizeof(original_config),
                           "%s/config", original_ssh) <
          sizeof(original_config));
    CHECK((size_t)snprintf(replacement_ssh, sizeof(replacement_ssh),
                           "%s/.ssh", g_replacement_home) <
          sizeof(replacement_ssh));
    snprintf(key, sizeof(key), "%s/id", root);
    make_account(&account, key);

    before = test_open_fd_count();
    g_home_create_retarget_succeeded = false;
    reset_dirsync_observations(&home_identity, false);
    previous_metadata = ssh_manager_set_metadata_test_hook_fn(
        retarget_home_before_ssh_create);
    previous_sync = ssh_manager_set_dirsync_fn(observe_dirsync);
    clear_error();
    CHECK_EQ_INT(ssh_configure_host_alias_result(&account, &publication), -1);
    failure = *get_last_error();
    ssh_manager_set_dirsync_fn(previous_sync);
    ssh_manager_set_metadata_test_hook_fn(previous_metadata);
    g_public_home_link[0] = '\0';
    g_replacement_home[0] = '\0';

    CHECK(g_home_create_retarget_succeeded);
    CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_PREINSTALL_FAILED);
    CHECK_EQ_INT(failure.code, ERR_FILE_IO);
    CHECK(strstr(failure.message, "HOME changed") != NULL);
    CHECK_EQ_INT(g_dirsync_observation_count, 1);
    CHECK(ts_same_identity(&g_dirsync_observations[0], &home_identity));
    CHECK_EQ_INT(lstat(original_ssh, &ssh_identity), 0);
    CHECK(S_ISDIR(ssh_identity.st_mode));
    CHECK_EQ_INT(ssh_identity.st_uid, getuid());
    CHECK_EQ_INT(ssh_identity.st_mode & 0777, 0700);
    errno = 0;
    CHECK(access(original_config, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT(count_temps_in(original_ssh), 0);
    errno = 0;
    CHECK(access(replacement_ssh, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT(test_open_fd_count(), before);
}

TEST(symlinked_home_retarget_during_parent_sync_fails_preinstall) {
    char root[96];
    char real_home[MAX_PATH_LEN], public_home[MAX_PATH_LEN];
    char config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    char original_ssh[MAX_PATH_LEN], original_config[MAX_PATH_LEN];
    char original_lock[MAX_PATH_LEN], replacement_ssh[MAX_PATH_LEN];
    account_t account;
    struct stat home_identity;
    struct stat replacement_identity;
    struct stat public_identity;
    struct stat ssh_identity;
    error_context_t failure;
    ssh_config_publication_state_t publication;
    ssh_dirsync_fn previous;
    int before;

    CHECK_EQ_INT(setup_symlinked_home(root, real_home, public_home, config), 0);
    CHECK((size_t)snprintf(g_replacement_home,
                           sizeof(g_replacement_home), "%s/replacement",
                           root) < sizeof(g_replacement_home));
    CHECK_EQ_INT(mkdir(g_replacement_home, 0700), 0);
    CHECK_EQ_INT(stat(real_home, &home_identity), 0);
    CHECK_EQ_INT(stat(g_replacement_home, &replacement_identity), 0);
    CHECK((size_t)snprintf(g_public_home_link,
                           sizeof(g_public_home_link), "%s", public_home) <
          sizeof(g_public_home_link));
    CHECK((size_t)snprintf(original_ssh, sizeof(original_ssh), "%s/.ssh",
                           real_home) < sizeof(original_ssh));
    CHECK((size_t)snprintf(original_config, sizeof(original_config),
                           "%s/config", original_ssh) <
          sizeof(original_config));
    CHECK((size_t)snprintf(original_lock, sizeof(original_lock),
                           "%s/.gitswitch-config.lock", original_ssh) <
          sizeof(original_lock));
    CHECK((size_t)snprintf(replacement_ssh, sizeof(replacement_ssh),
                           "%s/.ssh", g_replacement_home) <
          sizeof(replacement_ssh));
    snprintf(key, sizeof(key), "%s/id", root);
    make_account(&account, key);

    before = test_open_fd_count();
    reset_dirsync_observations(&home_identity, false);
    previous = ssh_manager_set_dirsync_fn(retarget_home_during_dirsync);
    clear_error();
    CHECK_EQ_INT(ssh_configure_host_alias_result(&account, &publication), -1);
    failure = *get_last_error();
    ssh_manager_set_dirsync_fn(previous);
    g_public_home_link[0] = '\0';
    g_replacement_home[0] = '\0';

    CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_PREINSTALL_FAILED);
    CHECK_EQ_INT(failure.code, ERR_FILE_IO);
    CHECK(strstr(failure.message, "HOME changed") != NULL);
    CHECK_EQ_INT(g_dirsync_observation_count, 1);
    CHECK(ts_same_identity(&g_dirsync_observations[0], &home_identity));
    CHECK_EQ_INT(stat(public_home, &public_identity), 0);
    CHECK(ts_same_identity(&public_identity, &replacement_identity));
    CHECK_EQ_INT(lstat(original_ssh, &ssh_identity), 0);
    CHECK(S_ISDIR(ssh_identity.st_mode));
    CHECK_EQ_INT(ssh_identity.st_uid, getuid());
    CHECK_EQ_INT(ssh_identity.st_mode & 0777, 0700);
    errno = 0;
    CHECK(access(original_config, F_OK) != 0 && errno == ENOENT);
    errno = 0;
    CHECK(access(original_lock, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT(count_temps_in(original_ssh), 0);
    errno = 0;
    CHECK(access(replacement_ssh, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT(test_open_fd_count(), before);
}

TEST(config_registration_failure_is_atomic_and_retryable) {
    char scratch[TEST_SCRATCH_PROBE_MAX][TEST_SCRATCH_PATH_SIZE];
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    char ssh_dir[MAX_PATH_LEN];
    account_t account;
    ssh_config_publication_state_t publication;
    size_t registered;
    size_t length = 0;
    char *content;
    int before;

    CHECK_EQ_INT(setup_home(home, config), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home);
    make_account(&account, key);

    before = test_open_fd_count();
    registered = test_scratch_fill(scratch, "ssh-full");
    CHECK(registered > 0 && registered < TEST_SCRATCH_PROBE_MAX);
    clear_error();
    CHECK_EQ_INT(ssh_configure_host_alias_result(&account, &publication), -1);
    CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_PREINSTALL_FAILED);
    CHECK(strstr(get_last_error()->message, "register") != NULL);
    errno = 0;
    CHECK(access(config, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT(count_temps_in(ssh_dir), 0);

    test_scratch_release(scratch, registered);
    CHECK_EQ_INT(test_open_fd_count(), before);
    clear_error();
    CHECK_EQ_INT(ssh_configure_host_alias_result(&account, &publication), 0);
    CHECK_EQ_INT(publication, SSH_CONFIG_PUBLICATION_COMMITTED);
    content = read_bytes(config, &length);
    CHECK(content != NULL);
    if (content) {
        CHECK(strstr(content, BEGIN_MARK) != NULL);
        free(content);
    }
    CHECK_EQ_INT(count_temps_in(ssh_dir), 0);
}

TEST(postrename_dirsync_failure_is_durability_uncertain_without_temp) {
    static const char original[] = "Host existing\n  User preserved\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN], ssh_dir[MAX_PATH_LEN];
    account_t account;
    ssh_dirsync_fn previous;
    ssh_config_publication_state_t publication;
    size_t length = 0;
    char *content;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home);
    make_account(&account, key);
    g_dirsync_calls = 0;
    previous = ssh_manager_set_dirsync_fn(fail_dirsync);
    CHECK_EQ_INT(ssh_configure_host_alias_result(&account, &publication), -1);
    ssh_manager_set_dirsync_fn(previous);
    CHECK_EQ_INT(publication,
                 SSH_CONFIG_PUBLICATION_DURABILITY_UNCERTAIN);
    CHECK_EQ_INT(g_dirsync_calls, 1);
    CHECK(strstr(get_last_error()->message, "replacement") != NULL);
    CHECK(strstr(get_last_error()->message, "uncertain") != NULL);
    content = read_bytes(config, &length);
    CHECK(content != NULL);
    if (content) {
        CHECK(strstr(content, BEGIN_MARK) != NULL);
        free(content);
    }
    CHECK_EQ_INT(count_temps_in(ssh_dir), 0);
}

TEST(postrename_verification_failure_reports_installed_unverified) {
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN], ssh_dir[MAX_PATH_LEN];
    account_t account;
    ssh_config_postrename_hook_fn previous;
    ssh_config_publication_state_t publication;
    size_t length = 0;
    char *content;

    CHECK_EQ_INT(setup_home(home, config), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home);
    make_account(&account, key);
    previous = ssh_manager_set_config_postrename_hook_fn(
        fail_postrename_verification);
    CHECK_EQ_INT(ssh_configure_host_alias_result(&account, &publication), -1);
    ssh_manager_set_config_postrename_hook_fn(previous);
    CHECK_EQ_INT(publication,
                 SSH_CONFIG_PUBLICATION_INSTALLED_UNVERIFIED);
    CHECK(strstr(get_last_error()->message, "installed") != NULL);
    CHECK(strstr(get_last_error()->message, "retained") != NULL);
    CHECK(strstr(get_last_error()->message, "uncertain") != NULL);
    content = read_bytes(config, &length);
    CHECK(content != NULL);
    if (content) {
        CHECK(strstr(content, BEGIN_MARK) != NULL);
        free(content);
    }
    CHECK_EQ_INT(count_temps_in(ssh_dir), 0);
}

TEST(ctime_only_drift_revalidates_exact_pinned_bytes) {
    static const char original[] = "Host preserved\n  User alice\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;
    ssh_config_commit_hook_fn previous;
    size_t length = 0;
    char *content;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);
    previous = ssh_manager_set_config_commit_hook_fn(
        advance_config_ctime_without_changing_bytes);
    CHECK_EQ_INT(ssh_configure_host_alias(&account), 0);
    ssh_manager_set_config_commit_hook_fn(previous);

    content = read_bytes(config, &length);
    CHECK(content != NULL);
    if (content) {
        CHECK(strstr(content, "Host preserved\n") != NULL);
        CHECK_EQ_INT(count_text(content, BEGIN_MARK), 1);
        free(content);
    }
}

TEST(ctime_only_metadata_shape_does_not_hide_content_change) {
    static const char original[] = "Host preserved\n  User alice\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN], ssh_dir[MAX_PATH_LEN];
    account_t account;
    ssh_config_commit_hook_fn previous;
    ssh_config_publication_state_t publication;
    size_t length = 0;
    char *content;

    CHECK_EQ_INT(setup_home(home, config), 0);
    CHECK_EQ_INT(write_bytes(config, original, sizeof(original) - 1U), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home);
    make_account(&account, key);
    previous = ssh_manager_set_config_commit_hook_fn(
        replace_config_byte_preserving_mtime);
    CHECK_EQ_INT(ssh_configure_host_alias_result(&account, &publication), -1);
    ssh_manager_set_config_commit_hook_fn(previous);
    CHECK_EQ_INT(publication,
                 SSH_CONFIG_PUBLICATION_PREINSTALL_FAILED);
    CHECK(strstr(get_last_error()->message, "bytes changed") != NULL);

    content = read_bytes(config, &length);
    CHECK(content != NULL);
    if (content) {
        CHECK_EQ_INT(length, sizeof(original) - 1U);
        CHECK(memcmp(content, original, sizeof(original) - 1U) != 0);
        CHECK_EQ_INT(count_text(content, BEGIN_MARK), 0);
        free(content);
    }
    CHECK_EQ_INT(count_temps_in(ssh_dir), 0);
}

TEST(pinned_directory_swap_fails_without_touching_replacement_or_leaking_temp) {
    static const char replacement[] = "Host replacement\n  User untouched\n";
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    char moved_config[MAX_PATH_LEN];
    account_t account;
    ssh_config_commit_hook_fn previous;
    struct stat moved_config_stat;
    size_t length = 0;
    char *content;

    CHECK_EQ_INT(setup_home(home, config), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);
    snprintf(g_public_ssh_dir, sizeof(g_public_ssh_dir), "%s/.ssh", home);
    snprintf(g_moved_ssh_dir, sizeof(g_moved_ssh_dir), "%s/.ssh.pinned", home);
    previous = ssh_manager_set_config_commit_hook_fn(
        swap_public_ssh_directory);
    CHECK_EQ_INT(ssh_configure_host_alias(&account), -1);
    ssh_manager_set_config_commit_hook_fn(previous);

    content = read_bytes(config, &length);
    CHECK(content != NULL);
    if (content) {
        CHECK_EQ_INT(length, sizeof(replacement) - 1U);
        CHECK(memcmp(content, replacement, sizeof(replacement) - 1U) == 0);
        free(content);
    }
    CHECK_EQ_INT(count_temps_in(g_public_ssh_dir), 0);
    CHECK_EQ_INT(count_temps_in(g_moved_ssh_dir), 0);
    CHECK((size_t)snprintf(moved_config, sizeof(moved_config), "%s/config",
                           g_moved_ssh_dir) < sizeof(moved_config));
    errno = 0;
    CHECK_EQ_INT(lstat(moved_config, &moved_config_stat), -1);
    CHECK_EQ_INT(errno, ENOENT);
}

TEST(first_ssh_creation_waits_for_home_namespace_lock) {
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    char ssh_dir[MAX_PATH_LEN];
    account_t account;
    struct stat identity;
    int started[2] = {-1, -1};
    int completed[2] = {-1, -1};
    int home_lock_fd = -1;
    pid_t child = -1;
    int status = 0;
    int completion_state;
    bool home_locked = false;
    bool completed_early = false;
    int before;

    if (setup_home_without_ssh(home, config) != 0 ||
        (size_t)snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home) >=
            sizeof(ssh_dir)) {
        CHECK(false);
        return;
    }
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);
    before = test_open_fd_count();
    home_lock_fd = open(home, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (home_lock_fd < 0 || flock(home_lock_fd, LOCK_EX) != 0 ||
        pipe(started) != 0 || pipe(completed) != 0) {
        CHECK(false);
        goto cleanup;
    }
    home_locked = true;

    child = fork();
    if (child < 0) {
        CHECK(false);
        goto cleanup;
    }
    if (child == 0) {
        int rc;
        int marker_rc;

        close_test_fd(&started[0]);
        close_test_fd(&completed[0]);
        close_test_fd(&home_lock_fd);
        if (write_marker(started[1], 's') != 0) _exit(10);
        close_test_fd(&started[1]);
        rc = ssh_configure_host_alias(&account);
        marker_rc = rc == 0 ? write_marker(completed[1], 'd') : -1;
        close_test_fd(&completed[1]);
        _exit(rc == 0 && marker_rc == 0 ? 0 : 11);
    }

    close_test_fd(&started[1]);
    close_test_fd(&completed[1]);
    if (wait_readable(started[0], 5000) != 1 ||
        read_marker(started[0]) != 0) {
        CHECK(false);
        goto cleanup;
    }
    close_test_fd(&started[0]);

    completion_state = wait_readable(completed[0], 1000);
    CHECK_EQ_INT(completion_state, 0);
    if (completion_state == 1) {
        completed_early = true;
        CHECK_EQ_INT(read_marker(completed[0]), 0);
    }
    errno = 0;
    CHECK(lstat(ssh_dir, &identity) != 0 && errno == ENOENT);

    CHECK_EQ_INT(flock(home_lock_fd, LOCK_UN), 0);
    home_locked = false;
    close_test_fd(&home_lock_fd);
    if (!completed_early) {
        completion_state = wait_readable(completed[0], 5000);
        CHECK_EQ_INT(completion_state, 1);
        if (completion_state == 1) {
            CHECK_EQ_INT(read_marker(completed[0]), 0);
        }
    }
    close_test_fd(&completed[0]);
    CHECK_EQ_INT(wait_child(child, &status, 5000), 0);
    child = -1;
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK_EQ_INT(lstat(ssh_dir, &identity), 0);
    CHECK(S_ISDIR(identity.st_mode));
    CHECK_EQ_INT(access(config, F_OK), 0);

cleanup:
    if (home_locked && home_lock_fd >= 0) {
        (void)flock(home_lock_fd, LOCK_UN);
    }
    close_test_fd(&home_lock_fd);
    close_test_fd(&started[0]);
    close_test_fd(&started[1]);
    close_test_fd(&completed[0]);
    close_test_fd(&completed[1]);
    if (child > 0) {
        CHECK_EQ_INT(wait_child(child, &status, 5000), 0);
    }
    CHECK_EQ_INT(test_open_fd_count(), before);
}

TEST(config_transaction_lock_prevents_two_process_lost_update) {
    char home[96], config[MAX_PATH_LEN];
    char first_key[MAX_PATH_LEN], second_key[MAX_PATH_LEN];
    char first_begin[128], first_end[128];
    char second_begin[128], second_end[128];
    account_t first_account, second_account;
    int first_ready[2] = {-1, -1};
    int first_release[2] = {-1, -1};
    int second_started[2] = {-1, -1};
    int second_commit[2] = {-1, -1};
    pid_t first_child = -1;
    pid_t second_child = -1;
    int first_status = 0;
    int second_status = 0;
    int commit_state;
    bool first_at_hook = false;
    bool first_released = false;
    bool second_reported_early = false;
    size_t config_len = 0;
    char *content = NULL;
    struct stat before;
    struct stat after;

    if (setup_home_without_ssh(home, config) != 0) {
        CHECK(false);
        return;
    }
    snprintf(first_key, sizeof(first_key), "%s/first key", home);
    snprintf(second_key, sizeof(second_key), "%s/second key", home);
    make_account(&first_account, first_key);
    make_account(&second_account, second_key);
    snprintf(second_account.ssh_host_alias,
             sizeof(second_account.ssh_host_alias), "%s", TEST_ALIAS_TWO);
    snprintf(second_account.ssh_hostname,
             sizeof(second_account.ssh_hostname), "%s", TEST_HOSTNAME_TWO);

    if (pipe(first_ready) != 0 || pipe(first_release) != 0 ||
        pipe(second_started) != 0 || pipe(second_commit) != 0) {
        CHECK(false);
        goto cleanup;
    }

    first_child = fork();
    if (first_child < 0) {
        CHECK(false);
        goto cleanup;
    }
    if (first_child == 0) {
        int rc;
        close_test_fd(&first_ready[0]);
        close_test_fd(&first_release[1]);
        close_test_fd(&second_started[0]);
        close_test_fd(&second_started[1]);
        close_test_fd(&second_commit[0]);
        close_test_fd(&second_commit[1]);
        g_transaction_ready_fd = first_ready[1];
        g_transaction_release_fd = first_release[0];
        (void)ssh_manager_set_config_commit_hook_fn(
            pause_while_holding_config_transaction);
        rc = ssh_configure_host_alias(&first_account);
        close_test_fd(&first_ready[1]);
        close_test_fd(&first_release[0]);
        _exit(rc == 0 ? 0 : 11);
    }

    close_test_fd(&first_ready[1]);
    close_test_fd(&first_release[0]);
    if (wait_readable(first_ready[0], 5000) != 1 ||
        read_marker(first_ready[0]) != 0) {
        CHECK(false);
        goto cleanup;
    }
    first_at_hook = true;
    close_test_fd(&first_ready[0]);

    second_child = fork();
    if (second_child < 0) {
        CHECK(false);
        goto cleanup;
    }
    if (second_child == 0) {
        int rc;
        close_test_fd(&first_release[1]);
        close_test_fd(&second_started[0]);
        close_test_fd(&second_commit[0]);
        g_transaction_commit_fd = second_commit[1];
        (void)ssh_manager_set_config_commit_hook_fn(report_config_commit);
        if (write_marker(second_started[1], 's') != 0) _exit(12);
        close_test_fd(&second_started[1]);
        rc = ssh_configure_host_alias(&second_account);
        close_test_fd(&second_commit[1]);
        _exit(rc == 0 ? 0 : 13);
    }

    close_test_fd(&second_started[1]);
    close_test_fd(&second_commit[1]);
    if (wait_readable(second_started[0], 5000) != 1 ||
        read_marker(second_started[0]) != 0) {
        CHECK(false);
        goto cleanup;
    }
    close_test_fd(&second_started[0]);

    /* Child one is paused in the pre-rename commit hook while still holding
     * the transaction lock.  Once child two has crossed its start barrier it
     * must remain outside its own commit hook until that lock is released. */
    commit_state = wait_readable(second_commit[0], 1000);
    CHECK_EQ_INT(commit_state, 0);
    if (commit_state == 1) {
        second_reported_early = true;
        CHECK_EQ_INT(read_marker(second_commit[0]), 0);
    }

    CHECK_EQ_INT(write_marker(first_release[1], 'r'), 0);
    first_released = true;
    close_test_fd(&first_release[1]);

    if (!second_reported_early) {
        commit_state = wait_readable(second_commit[0], 5000);
        CHECK_EQ_INT(commit_state, 1);
        if (commit_state == 1) {
            CHECK_EQ_INT(read_marker(second_commit[0]), 0);
        }
    }
    close_test_fd(&second_commit[0]);

    CHECK_EQ_INT(wait_child(first_child, &first_status, 5000), 0);
    first_child = -1;
    CHECK(WIFEXITED(first_status) && WEXITSTATUS(first_status) == 0);
    CHECK_EQ_INT(wait_child(second_child, &second_status, 5000), 0);
    second_child = -1;
    CHECK(WIFEXITED(second_status) && WEXITSTATUS(second_status) == 0);

    snprintf(first_begin, sizeof(first_begin),
             "# >>> gitswitch %s >>>", TEST_ALIAS);
    snprintf(first_end, sizeof(first_end),
             "# <<< gitswitch %s <<<", TEST_ALIAS);
    snprintf(second_begin, sizeof(second_begin),
             "# >>> gitswitch %s >>>", TEST_ALIAS_TWO);
    snprintf(second_end, sizeof(second_end),
             "# <<< gitswitch %s <<<", TEST_ALIAS_TWO);
    content = read_bytes(config, &config_len);
    CHECK(content != NULL);
    if (content) {
        CHECK_EQ_INT(count_text(content, first_begin), 1);
        CHECK_EQ_INT(count_text(content, first_end), 1);
        CHECK_EQ_INT(count_text(content, second_begin), 1);
        CHECK_EQ_INT(count_text(content, second_end), 1);
        CHECK_EQ_INT(count_text(content, "Host github-work\n"), 1);
        CHECK_EQ_INT(count_text(content, "  HostName github.com\n"), 1);
        CHECK_EQ_INT(count_text(content, "Host gitlab-personal\n"), 1);
        CHECK_EQ_INT(count_text(content, "  HostName gitlab.com\n"), 1);
        free(content);
        content = NULL;
    }

    /* A byte-identical configure of the last block makes the production
     * parser accept the complete interleaved result without masking a lost
     * first update through a repair write. */
    CHECK_EQ_INT(stat(config, &before), 0);
    CHECK_EQ_INT(ssh_configure_host_alias(&second_account), 0);
    CHECK_EQ_INT(stat(config, &after), 0);
    CHECK(before.st_dev == after.st_dev);
    CHECK(before.st_ino == after.st_ino);
    CHECK(same_mtime(&before, &after));

cleanup:
    free(content);
    if (first_at_hook && !first_released && first_release[1] >= 0) {
        (void)write_marker(first_release[1], 'r');
    }
    close_test_fd(&first_ready[0]);
    close_test_fd(&first_ready[1]);
    close_test_fd(&first_release[0]);
    close_test_fd(&first_release[1]);
    close_test_fd(&second_started[0]);
    close_test_fd(&second_started[1]);
    close_test_fd(&second_commit[0]);
    close_test_fd(&second_commit[1]);
    if (first_child > 0) {
        CHECK_EQ_INT(wait_child(first_child, &first_status, 5000), 0);
    }
    if (second_child > 0) {
        CHECK_EQ_INT(wait_child(second_child, &second_status, 5000), 0);
    }
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(identityfile_quoting_and_hostname_are_serialized_safely);
    RUN_TEST(host_port_hostname_is_rejected_without_mutating_config);
    RUN_TEST(historical_host_port_block_can_be_repaired_after_upgrade);
    RUN_TEST(historical_host_port_block_can_be_removed_after_upgrade);
    RUN_TEST(identityfile_quoting_and_hostname_match_openssh_oracle);
    RUN_TEST(openssh_include_rejects_other_writable_config);
    RUN_TEST(openssh_percent_and_environment_expansions_are_safe);
    RUN_TEST(embedded_nul_at_every_region_fails_without_mutation);
    RUN_TEST(exact_marker_parser_preserves_incidental_substrings);
    RUN_TEST(earlier_unmanaged_catchall_is_rejected_before_alias_publication);
    RUN_TEST(earlier_unmanaged_wildcard_match_is_rejected_before_alias_publication);
    RUN_TEST(earlier_unmanaged_second_whitespace_pattern_is_rejected_before_publication);
    RUN_TEST(earlier_managed_wildcard_overlap_is_rejected_before_alias_publication);
    RUN_TEST(later_managed_wildcard_identity_accumulation_is_rejected_before_publication);
    RUN_TEST(negated_unmanaged_wildcard_exception_does_not_conflict);
    RUN_TEST(escaped_leading_bang_is_literal_and_wildcard_still_conflicts);
    RUN_TEST(comma_separated_text_is_one_nonmatching_pattern);
    RUN_TEST(similar_exact_alias_does_not_conflict);
    RUN_TEST(wildcard_target_pattern_conflicting_with_exact_host_is_rejected);
    RUN_TEST(question_target_pattern_conflicting_with_exact_host_is_rejected);
    RUN_TEST(case_insensitive_indented_host_equals_directive_is_rejected);
    RUN_TEST(bare_carriage_return_host_whitespace_is_rejected);
    RUN_TEST(host_patterns_remain_case_sensitive);
    RUN_TEST(matching_host_with_proxy_command_is_permitted);
    RUN_TEST(matching_host_with_harmless_options_is_permitted);
    RUN_TEST(matching_host_with_certificate_file_is_rejected);
    RUN_TEST(matching_host_with_hostname_only_is_rejected);
    RUN_TEST(matching_host_with_identity_file_only_is_rejected);
    RUN_TEST(matching_host_with_identities_only_is_rejected);
    RUN_TEST(overlong_host_pattern_fails_closed_before_publication);
    RUN_TEST(include_directive_fails_closed_before_alias_publication);
    RUN_TEST(match_directive_fails_closed_before_alias_publication);
    RUN_TEST(global_routing_options_fail_closed_before_alias_publication);
    RUN_TEST(malformed_nested_and_mismatched_blocks_fail_closed);
    RUN_TEST(valid_duplicates_collapse_to_one_then_remove_to_zero);
    RUN_TEST(crlf_duplicates_collapse_and_preserve_unrelated_bytes);
    RUN_TEST(crlf_remove_preserves_all_unmanaged_bytes);
    RUN_TEST(byte_identical_config_skips_all_write_and_sync_work);
    RUN_TEST(byte_identical_safe_config_rechecks_mode_before_noop);
    RUN_TEST(byte_identical_safe_config_rebinds_final_public_directory);
    RUN_TEST(byte_identical_safe_hardlink_remains_unchanged);
    RUN_TEST(byte_identical_writable_mode_matrix_is_atomically_normalized);
    RUN_TEST(byte_identical_writable_hardlink_is_replaced_not_chmodded);
    RUN_TEST(byte_identical_writable_preinstall_failure_preserves_original);
    RUN_TEST(byte_identical_writable_postrename_failure_reports_installed);
    RUN_TEST(byte_identical_writable_dirsync_failure_reports_uncertain);
    RUN_TEST(first_ssh_directory_syncs_home_before_child);
    RUN_TEST(first_ssh_directory_home_sync_failure_is_preinstall_and_retryable);
    RUN_TEST(existing_ssh_directory_syncs_only_child);
    RUN_TEST(configless_existing_ssh_syncs_parent_before_first_publication);
    RUN_TEST(symlinked_home_first_publication_syncs_resolved_parent);
    RUN_TEST(descriptor_relative_first_creation_ignores_home_retarget);
    RUN_TEST(symlinked_home_retarget_during_parent_sync_fails_preinstall);
    RUN_TEST(config_registration_failure_is_atomic_and_retryable);
    RUN_TEST(postrename_dirsync_failure_is_durability_uncertain_without_temp);
    RUN_TEST(postrename_verification_failure_reports_installed_unverified);
    RUN_TEST(ctime_only_drift_revalidates_exact_pinned_bytes);
    RUN_TEST(ctime_only_metadata_shape_does_not_hide_content_change);
    RUN_TEST(pinned_directory_swap_fails_without_touching_replacement_or_leaking_temp);
    RUN_TEST(first_ssh_creation_waits_for_home_namespace_lock);
    RUN_TEST(config_transaction_lock_prevents_two_process_lost_update);
TEST_MAIN_END()
