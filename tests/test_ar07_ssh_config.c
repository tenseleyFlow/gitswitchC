/* AR-07 T9: adversarial SSH user-config serialization and replacement. */
#ifdef __linux__
#define _GNU_SOURCE
#endif

#include "test.h"
#include "error.h"
#include "gitswitch.h"
#include "ssh_manager.h"
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
static char g_public_ssh_dir[MAX_PATH_LEN];
static char g_moved_ssh_dir[MAX_PATH_LEN];
static int g_transaction_ready_fd = -1;
static int g_transaction_release_fd = -1;
static int g_transaction_commit_fd = -1;

static int setup_home(char home[96], char config[MAX_PATH_LEN]) {
    char ssh_dir[MAX_PATH_LEN];

    snprintf(home, 96, "/tmp/gswar07sshcfgXXXXXX");
    if (!ts_mkdtemp(home) || setenv("HOME", home, 1) != 0) return -1;
    if ((size_t)snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", home) >=
            sizeof(ssh_dir) ||
        mkdir(ssh_dir, 0700) != 0 ||
        (size_t)snprintf(config, MAX_PATH_LEN, "%s/config", ssh_dir) >=
            MAX_PATH_LEN) {
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

static int fail_postrename_verification(int dir_fd) {
    (void)dir_fd;
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

TEST(identityfile_quoting_and_hostname_match_openssh_oracle) {
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
    CHECK(output_has_value(output, "hostname", TEST_HOSTNAME));
    CHECK(output_has_value(output, "identityfile", key));
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
        BEGIN_MARK "\nHost " TEST_ALIAS "\n  ProxyCommand false\n" END_MARK "\n"
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

TEST(byte_identical_config_skips_all_write_and_sync_work) {
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN];
    account_t account;
    struct stat before;
    struct stat after;
    ssh_dirsync_fn previous;

    CHECK_EQ_INT(setup_home(home, config), 0);
    snprintf(key, sizeof(key), "%s/id", home);
    make_account(&account, key);
    CHECK_EQ_INT(ssh_configure_host_alias(&account), 0);
    CHECK_EQ_INT(stat(config, &before), 0);
    g_dirsync_calls = 0;
    previous = ssh_manager_set_dirsync_fn(fail_dirsync);
    CHECK_EQ_INT(ssh_configure_host_alias(&account), 0);
    ssh_manager_set_dirsync_fn(previous);
    CHECK_EQ_INT(g_dirsync_calls, 0);
    CHECK_EQ_INT(stat(config, &after), 0);
    CHECK(before.st_ino == after.st_ino);
    CHECK(same_mtime(&before, &after));
}

TEST(postrename_dirsync_failure_is_changed_uncertain_without_temp) {
    char home[96], config[MAX_PATH_LEN], key[MAX_PATH_LEN], ssh_dir[MAX_PATH_LEN];
    account_t account;
    ssh_dirsync_fn previous;
    ssh_config_publication_state_t publication;
    size_t length = 0;
    char *content;

    CHECK_EQ_INT(setup_home(home, config), 0);
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
    CHECK(strstr(get_last_error()->message, "changed bytes") != NULL);
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

    if (setup_home(home, config) != 0) {
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
    RUN_TEST(identityfile_quoting_and_hostname_match_openssh_oracle);
    RUN_TEST(openssh_percent_and_environment_expansions_are_safe);
    RUN_TEST(embedded_nul_at_every_region_fails_without_mutation);
    RUN_TEST(exact_marker_parser_preserves_incidental_substrings);
    RUN_TEST(malformed_nested_and_mismatched_blocks_fail_closed);
    RUN_TEST(valid_duplicates_collapse_to_one_then_remove_to_zero);
    RUN_TEST(byte_identical_config_skips_all_write_and_sync_work);
    RUN_TEST(postrename_dirsync_failure_is_changed_uncertain_without_temp);
    RUN_TEST(postrename_verification_failure_reports_installed_unverified);
    RUN_TEST(ctime_only_drift_revalidates_exact_pinned_bytes);
    RUN_TEST(ctime_only_metadata_shape_does_not_hide_content_change);
    RUN_TEST(pinned_directory_swap_fails_without_touching_replacement_or_leaking_temp);
    RUN_TEST(config_transaction_lock_prevents_two_process_lost_update);
TEST_MAIN_END()
