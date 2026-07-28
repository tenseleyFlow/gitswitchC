/* AR-07 T12: lossless schema admission and crash-truthful persistence. */
#include "test.h"
#include "config.h"
#include "error.h"
#include "scratch_registry_test.h"
#include "signals.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/wait.h>
#include <time.h>

static const char one_account[] =
    "[settings]\n"
    "default_scope = \"local\"\n"
    "[accounts.1]\n"
    "name = \"alice\"\n"
    "email = \"alice@example.com\"\n"
    "description = \"v0\"\n";

static const char two_accounts_legacy[] =
    "[settings]\n"
    "default_scope = \"local\"\n"
    "active_account = \"alice\"\n"
    "[accounts.1]\n"
    "name = \"alice\"\n"
    "email = \"alice@example.com\"\n"
    "[accounts.2]\n"
    "name = \"Bob\"\n"
    "email = \"bob@example.com\"\n";

static const char replacement_account[] =
    "[settings]\n"
    "default_scope = \"local\"\n"
    "[accounts.9]\n"
    "name = \"carol\"\n"
    "email = \"carol@example.com\"\n";

static int private_dir(char *path, size_t size) {
    if ((size_t)snprintf(path, size, "/tmp/gsw-ar07-config.XXXXXX") >= size) {
        return -1;
    }
    return ts_mkdtemp(path) ? 0 : -1;
}

static int write_private(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    size_t length = strlen(text);
    size_t total = 0;

    if (fd < 0) return -1;
    while (total < length) {
        ssize_t n = write(fd, text + total, length - total);
        if (n > 0) total += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else { close(fd); return -1; }
    }
    if (close(fd) != 0) return -1;
    return chmod(path, 0600);
}

static size_t read_text(const char *path, char *text, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    size_t total = 0;

    if (fd < 0 || size == 0) {
        if (fd >= 0) close(fd);
        return 0;
    }
    while (total + 1 < size) {
        ssize_t n = read(fd, text + total, size - total - 1);
        if (n > 0) total += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else break;
    }
    close(fd);
    text[total] = '\0';
    return total;
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

static bool same_identity(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
           left->st_size == right->st_size && same_mtime(left, right);
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

static bool same_without_ctime(const struct stat *left,
                               const struct stat *right) {
    return same_identity(left, right) && left->st_uid == right->st_uid &&
           left->st_gid == right->st_gid && left->st_mode == right->st_mode &&
           left->st_nlink == right->st_nlink;
}

static int force_ctime_only_drift(const char *path,
                                  const struct stat *expected,
                                  struct stat *current) {
    const struct timespec retry = { .tv_sec = 0, .tv_nsec = 1000000L };

    for (size_t attempt = 0; attempt < 128U; attempt++) {
        if (lstat(path, current) != 0 ||
            !same_without_ctime(expected, current)) {
            errno = ESTALE;
            return -1;
        }
        if (!same_ctime(expected, current)) return 0;
        if (chmod(path, 0400) != 0 || chmod(path, 0600) != 0) return -1;
        (void)nanosleep(&retry, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

static int restore_file_times(const char *path,
                              const struct stat *expected) {
    struct timespec times[2];

#ifdef __APPLE__
    times[0] = expected->st_atimespec;
    times[1] = expected->st_mtimespec;
#else
    times[0] = expected->st_atim;
    times[1] = expected->st_mtim;
#endif
    return utimensat(AT_FDCWD, path, times, 0);
}

static int rewrite_first_byte_preserving_mtime(
    const char *path, const struct stat *expected, unsigned char replacement,
    unsigned char *previous) {
    unsigned char observed;
    int fd;
    int saved_errno;

    fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (pread(fd, &observed, 1U, 0) != 1 ||
        pwrite(fd, &replacement, 1U, 0) != 1 || fsync(fd) != 0) {
        saved_errno = errno ? errno : EIO;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    if (close(fd) != 0) return -1;
    if (restore_file_times(path, expected) != 0) return -1;
    if (previous) *previous = observed;
    return 0;
}

static int count_prefix(const char *dir, const char *prefix) {
    DIR *stream = opendir(dir);
    struct dirent *entry;
    int count = 0;

    if (!stream) return -1;
    while ((entry = readdir(stream)) != NULL) {
        if (strncmp(entry->d_name, prefix, strlen(prefix)) == 0) count++;
    }
    closedir(stream);
    return count;
}

static int count_open_fds(void) {
    long limit = sysconf(_SC_OPEN_MAX);
    int count = 0;

    if (limit < 0 || limit > 4096) limit = 4096;
    for (int fd = 0; fd < (int)limit; fd++) {
        if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) count++;
    }
    return count;
}

static config_io_boundary_t fault_target;
static char generation_swap_source[256];
static char generation_swap_replacement[256];
static int generation_swap_error;
static config_io_boundary_t generation_swap_boundary;
static config_io_boundary_t rollback_replace_boundary;
static char rollback_replace_hint[256];
static char rollback_replace_source[256];
static int rollback_replace_error;
static size_t generation_document_malloc_calls;
static size_t generation_io_boundary_calls;
static char state_rewrite_hint[256];
static char state_rewrite_content[64];
static int state_rewrite_error;
static bool state_rewrite_restore_times;
static struct stat state_rewrite_expected;
static char state_ctime_drift_hint[256];
static int state_ctime_drift_error;
static char document_close_ctime_path[256];
static int document_close_ctime_error;
static char document_reproof_ctime_path[256];
static int document_reproof_ctime_error;
static char document_prepublication_ctime_path[256];
static int document_prepublication_ctime_error;
static char document_rewrite_path[256];
static const char *document_rewrite_content;
static struct stat document_rewrite_before;
static struct stat document_rewrite_after;
static int document_rewrite_error;
static size_t document_dir_observations;
static char noop_state_rewrite_hint[256];
static char noop_state_rewrite_content[64];
static struct stat noop_state_rewrite_before;
static struct stat noop_state_rewrite_after;
static int noop_state_rewrite_error;

static bool inject_fault(config_io_boundary_t boundary) {
    return boundary == fault_target;
}

static void *count_generation_document_malloc(size_t size) {
    generation_document_malloc_calls++;
    return malloc(size);
}

static bool count_generation_io_boundary(config_io_boundary_t boundary) {
    (void)boundary;
    generation_io_boundary_calls++;
    return false;
}

static bool count_document_dir_observation(
    config_metadata_test_stage_t stage) {
    if (stage == CONFIG_METADATA_TEST_DOCUMENT_DIR) {
        document_dir_observations++;
    }
    return false;
}

static int rewrite_private_in_place(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    size_t length = strlen(text);
    size_t total = 0;

    if (fd < 0) return -1;
    while (total < length) {
        ssize_t written = write(fd, text + total, length - total);
        if (written > 0) total += (size_t)written;
        else if (written < 0 && errno == EINTR) continue;
        else { close(fd); return -1; }
    }
    if (fsync(fd) != 0) { close(fd); return -1; }
    return close(fd);
}

static bool rewrite_state_before_publication(
    config_io_boundary_t boundary) {
    if (boundary == CONFIG_IO_STATE_BEFORE_RENAME &&
        state_rewrite_hint[0] != '\0') {
        if (rewrite_private_in_place(state_rewrite_hint,
                                     state_rewrite_content) != 0 ||
            (state_rewrite_restore_times &&
             restore_file_times(state_rewrite_hint,
                                &state_rewrite_expected) != 0)) {
            state_rewrite_error = errno ? errno : EIO;
        }
        state_rewrite_hint[0] = '\0';
        state_rewrite_restore_times = false;
    }
    return false;
}

static bool drift_state_ctime_before_publication(
    config_io_boundary_t boundary) {
    struct stat before;
    struct stat after;

    if (boundary == CONFIG_IO_STATE_BEFORE_RENAME &&
        state_ctime_drift_hint[0] != '\0') {
        if (lstat(state_ctime_drift_hint, &before) != 0 ||
            force_ctime_only_drift(state_ctime_drift_hint, &before,
                                   &after) != 0) {
            state_ctime_drift_error = errno ? errno : EIO;
        }
        state_ctime_drift_hint[0] = '\0';
    }
    return false;
}

static bool drift_document_ctime_after_close(
    config_io_boundary_t boundary) {
    struct stat before;
    struct stat after;

    if (boundary == CONFIG_IO_DOCUMENT_AFTER_CLOSE &&
        document_close_ctime_path[0] != '\0') {
        if (lstat(document_close_ctime_path, &before) != 0 ||
            force_ctime_only_drift(document_close_ctime_path, &before,
                                   &after) != 0) {
            document_close_ctime_error = errno ? errno : EIO;
        }
        document_close_ctime_path[0] = '\0';
    }
    return false;
}

static bool drift_document_ctime_during_reproof(
    config_io_boundary_t boundary) {
    struct stat before;
    struct stat after;

    if (boundary == CONFIG_IO_DOCUMENT_REPROOF_AFTER_BYTES &&
        document_reproof_ctime_path[0] != '\0') {
        if (lstat(document_reproof_ctime_path, &before) != 0 ||
            force_ctime_only_drift(document_reproof_ctime_path, &before,
                                   &after) != 0) {
            document_reproof_ctime_error = errno ? errno : EIO;
        }
        document_reproof_ctime_path[0] = '\0';
    }
    return false;
}

static bool drift_document_ctime_before_publication(
    config_io_boundary_t boundary) {
    struct stat before;
    struct stat after;

    if (boundary == CONFIG_IO_DOCUMENT_BEFORE_RENAME &&
        document_prepublication_ctime_path[0] != '\0') {
        if (lstat(document_prepublication_ctime_path, &before) != 0 ||
            force_ctime_only_drift(
                document_prepublication_ctime_path, &before, &after) != 0) {
            document_prepublication_ctime_error = errno ? errno : EIO;
        }
        document_prepublication_ctime_path[0] = '\0';
    }
    return false;
}

static bool rewrite_document_before_directory_sync(
    config_io_boundary_t boundary) {
    if (boundary == CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC &&
        document_rewrite_path[0] != '\0') {
        if (lstat(document_rewrite_path, &document_rewrite_before) != 0 ||
            rewrite_private_in_place(document_rewrite_path,
                                     document_rewrite_content) != 0 ||
            lstat(document_rewrite_path, &document_rewrite_after) != 0) {
            document_rewrite_error = errno ? errno : EIO;
        }
        document_rewrite_path[0] = '\0';
    }
    return false;
}

static bool replace_source_at_state_publication(
    config_io_boundary_t boundary) {
    if (boundary == generation_swap_boundary &&
        generation_swap_source[0] != '\0') {
        if (rename(generation_swap_replacement,
                   generation_swap_source) != 0) {
            generation_swap_error = errno ? errno : EIO;
        }
        generation_swap_source[0] = '\0';
    }
    return false;
}

static bool rewrite_noop_state_before_directory_sync(
    config_io_boundary_t boundary) {
    if (boundary == CONFIG_IO_STATE_BEFORE_DIR_SYNC &&
        noop_state_rewrite_hint[0] != '\0') {
        if (lstat(noop_state_rewrite_hint,
                  &noop_state_rewrite_before) != 0 ||
            rewrite_private_in_place(noop_state_rewrite_hint,
                                     noop_state_rewrite_content) != 0 ||
            restore_file_times(noop_state_rewrite_hint,
                               &noop_state_rewrite_before) != 0 ||
            force_ctime_only_drift(noop_state_rewrite_hint,
                                   &noop_state_rewrite_before,
                                   &noop_state_rewrite_after) != 0) {
            noop_state_rewrite_error = errno ? errno : EIO;
        }
        noop_state_rewrite_hint[0] = '\0';
    }
    return false;
}

static bool replace_state_before_rollback(config_io_boundary_t boundary) {
    if (boundary != rollback_replace_boundary ||
        rollback_replace_hint[0] == '\0') {
        return false;
    }
    if (rename(rollback_replace_source, rollback_replace_hint) != 0) {
        rollback_replace_error = errno ? errno : EIO;
    }
    rollback_replace_hint[0] = '\0';
    return true;
}

static bool kill_at_default_boundary(config_io_boundary_t boundary) {
    if (boundary == fault_target) {
        raise(SIGTERM); /* deferred */
        raise(SIGTERM); /* emergency cleanup + truthful signal death */
    }
    return false;
}

static int fixed_clock(uint64_t *seconds, uint32_t *nanoseconds) {
    *seconds = 1234;
    *nanoseconds = 567;
    return 0;
}

static config_backup_readdir_fn backup_readdir_underlying;
static unsigned int backup_readdir_scan;
static unsigned int backup_readdir_candidates;
static bool backup_readdir_failed;

static struct dirent *fail_second_backup_scan_mid_enumeration(DIR *dir) {
    struct dirent *entry;

    if (backup_readdir_scan == 1 && backup_readdir_candidates == 6) {
        backup_readdir_failed = true;
        errno = EIO;
        return NULL;
    }
    errno = 0;
    entry = backup_readdir_underlying(dir);
    if (!entry) {
        if (errno == 0) {
            backup_readdir_scan++;
            backup_readdir_candidates = 0;
        }
        return NULL;
    }
    if (backup_readdir_scan == 1 &&
        strncmp(entry->d_name, "accounts.toml.backup.",
                strlen("accounts.toml.backup.")) == 0) {
        backup_readdir_candidates++;
    }
    return entry;
}

static int backup_generation_path(char *path, size_t size,
                                  const char *config_path,
                                  unsigned long long generation) {
    int needed = snprintf(path, size,
                          "%s.backup.%020llu.%09u.%020llu",
                          config_path, 1234ULL, 567U, generation);
    return needed < 0 || (size_t)needed >= size ? -1 : 0;
}

static void expect_load_error(const char *body, const char *needle) {
    char dir[128], path[256];
    gitswitch_ctx_t ctx;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_private(path, body), 0);
    memset(&ctx, 0, sizeof(ctx));
    clear_error();
    CHECK_EQ_INT(config_load(&ctx, path), -1);
    CHECK(strstr(get_last_error()->message, needle) != NULL);
}

/* AR-13 M7: a hand-edited account with a dependent key but no enabling key is
 * an own-writer-shaped edit, so it is skipped (counted, rewrite-blocked) and
 * the rest of the config still loads — not a whole-file brick. The body carries
 * one bad [accounts.1] plus a valid [accounts.2] that must survive. */
static void expect_dependency_gap_section_skipped(const char *body) {
    char dir[128], path[256];
    gitswitch_ctx_t ctx;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_private(path, body), 0);
    memset(&ctx, 0, sizeof(ctx));
    clear_error();
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 1);
    CHECK_EQ_INT(config_check_rewritable(&ctx), -1);
}

TEST(schema_rejects_lossy_types_and_dependent_keys) {
    expect_load_error("[settings]\ndefault_scope=\"local\"\nactive_account=7\n",
                      "active_account must be a string");
    expect_load_error("[settings]\ndefault_scope=\"sideways\"\n",
                      "default_scope must be 'local' or 'global'");
    expect_load_error("[settings]\ndefault_scope=\"local\"\n"
                      "[accounts.1]\nname=\"alice\"\nemail=\"a@b.com\"\n"
                      "description=7\n", "description must be a string");
    expect_load_error("[settings]\ndefault_scope=\"local\"\n"
                      "[accounts.1]\nname=\"alice\"\nemail=\"a@b.com\"\n"
                      "preferred_scope=\"system\"\n",
                      "preferred_scope must be 'local' or 'global'");
    expect_load_error("[settings]\ndefault_scope=\"local\"\n"
                      "[accounts.1]\nname=\"alice\"\nemail=\"a@b.com\"\n"
                      "gpg_signing_enabled=1\n",
                      "gpg_signing_enabled must be a boolean");
    expect_load_error("[settings]\ndefault_scope=\"local\"\n"
                      "[accounts.1]\nname=\"alice\"\nemail=\"a@b.com\"\n"
                      "gpg_key=7\n",
                      "gpg_key must be a string");
    /* A malformed string selector is account-local, but it must not hide a
     * later structural error in the same section. */
    expect_load_error("[settings]\ndefault_scope=\"local\"\n"
                      "[accounts.1]\nname=\"alice\"\nemail=\"a@b.com\"\n"
                      "gpg_key=\"NOT-A-HEX-SELECTOR\"\n"
                      "gpg_signing_enabled=1\n",
                      "gpg_signing_enabled must be a boolean");
    /* AR-13 M7: the three cross-field DEPENDENCY gaps now skip the offending
     * section instead of bricking the whole file (unlike the type errors
     * above, which stay hard rejects). A valid sibling account still loads. */
    expect_dependency_gap_section_skipped(
        "[settings]\ndefault_scope=\"local\"\n"
        "[accounts.1]\nname=\"alice\"\nemail=\"a@b.com\"\n"
        "ssh_host=\"github.com\"\n"
        "[accounts.2]\nname=\"bob\"\nemail=\"b@b.com\"\n");
    expect_dependency_gap_section_skipped(
        "[settings]\ndefault_scope=\"local\"\n"
        "[accounts.1]\nname=\"alice\"\nemail=\"a@b.com\"\n"
        "ssh_key=\"\"\nssh_hostname=\"github.com\"\n"
        "[accounts.2]\nname=\"bob\"\nemail=\"b@b.com\"\n");
    expect_dependency_gap_section_skipped(
        "[settings]\ndefault_scope=\"local\"\n"
        "[accounts.1]\nname=\"alice\"\nemail=\"a@b.com\"\n"
        "gpg_key=\"\"\ngpg_signing_enabled=false\n"
        "[accounts.2]\nname=\"bob\"\nemail=\"b@b.com\"\n");
}

TEST(malformed_gpg_selector_skips_only_its_account_and_blocks_rewrite) {
    static const char source[] =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"alice@example.com\"\n"
        "[accounts.2]\n"
        "name = \"broken\"\n"
        "email = \"broken@example.com\"\n"
        "gpg_key = \"NOT-A-HEX-SELECTOR\"\n"
        "gpg_signing_enabled = false\n"
        "[accounts.3]\n"
        "name = \"carol\"\n"
        "email = \"carol@example.com\"\n";
    char dir[128], path[256], observed[sizeof(source) + 32U];
    gitswitch_ctx_t ctx;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_private(path, source), 0);

    memset(&ctx, 0, sizeof(ctx));
    clear_error();
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);
    CHECK_EQ_INT(ctx.account_count, 2);
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 1);
    if (ctx.account_count == 2) {
        CHECK_EQ_INT(ctx.accounts[0].id, 1);
        CHECK_STR_EQ(ctx.accounts[0].name, "alice");
        CHECK_EQ_INT(ctx.accounts[1].id, 3);
        CHECK_STR_EQ(ctx.accounts[1].name, "carol");
    }
    CHECK_EQ_INT((long)read_text(path, observed, sizeof(observed)),
                 (long)strlen(source));
    CHECK(memcmp(observed, source, sizeof(source)) == 0);

    clear_error();
    CHECK_EQ_INT(config_check_rewritable(&ctx), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_CONFIG_INVALID);

    clear_error();
    CHECK_EQ_INT(config_save(&ctx, path), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_CONFIG_INVALID);
    CHECK_EQ_INT((long)read_text(path, observed, sizeof(observed)),
                 (long)strlen(source));
    CHECK(memcmp(observed, source, sizeof(source)) == 0);
    ts_rm_rf(dir);
}

TEST(default_create_fault_matrix_is_atomic_and_closes_fds) {
    const config_io_boundary_t pre_install[] = {
        CONFIG_IO_DEFAULT_AFTER_TEMP,
        CONFIG_IO_DEFAULT_AFTER_WRITE,
        CONFIG_IO_DEFAULT_BEFORE_FILE_SYNC,
        CONFIG_IO_DEFAULT_BEFORE_CLOSE,
        CONFIG_IO_DEFAULT_BEFORE_RENAME
    };
    char dir[128], path[256], text[2048];
    int before;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    for (size_t i = 0; i < sizeof(pre_install) / sizeof(pre_install[0]); i++) {
        snprintf(path, sizeof(path), "%s/default%zu.toml", dir, i);
        fault_target = pre_install[i];
        config_set_io_fault_fn(inject_fault);
        CHECK_EQ_INT(config_create_default(path), -1);
        CHECK(access(path, F_OK) != 0);
        CHECK_EQ_INT(count_prefix(dir, "default"), 0);
    }

    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    before = count_open_fds();
    fault_target = CONFIG_IO_DEFAULT_BEFORE_CLOSE;
    for (int i = 0; i < 32; i++) CHECK_EQ_INT(config_create_default(path), -1);
    CHECK_EQ_INT(count_open_fds(), before);
    CHECK(access(path, F_OK) != 0);

    fault_target = CONFIG_IO_DEFAULT_BEFORE_DIR_SYNC;
    CHECK_EQ_INT(config_create_default(path), -1);
    CHECK(read_text(path, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, default_config_template);
    config_set_io_fault_fn(NULL);
}

TEST(default_create_signal_death_is_truthful_at_every_boundary) {
    const config_io_boundary_t boundaries[] = {
        CONFIG_IO_DEFAULT_AFTER_TEMP,
        CONFIG_IO_DEFAULT_AFTER_WRITE,
        CONFIG_IO_DEFAULT_BEFORE_FILE_SYNC,
        CONFIG_IO_DEFAULT_BEFORE_CLOSE,
        CONFIG_IO_DEFAULT_BEFORE_RENAME,
        CONFIG_IO_DEFAULT_BEFORE_DIR_SYNC
    };
    char dir[128], path[256], leaf[64], prefix[80], text[2048];

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    for (size_t i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); i++) {
        pid_t child;
        int status = 0;

        snprintf(leaf, sizeof(leaf), "death%zu.toml", i);
        snprintf(path, sizeof(path), "%s/%s", dir, leaf);
        snprintf(prefix, sizeof(prefix), "%s.create.", leaf);
        fault_target = boundaries[i];
        child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            if (signals_guard_begin() != 0) _exit(90);
            config_set_io_fault_fn(kill_at_default_boundary);
            (void)config_create_default(path);
            _exit(91);
        }
        if (child < 0) continue;
        CHECK_EQ_INT(waitpid(child, &status, 0), child);
        CHECK(WIFSIGNALED(status));
        if (WIFSIGNALED(status)) {
            CHECK_EQ_INT(WTERMSIG(status), SIGTERM);
        }

        if (boundaries[i] == CONFIG_IO_DEFAULT_BEFORE_DIR_SYNC) {
            CHECK(read_text(path, text, sizeof(text)) > 0);
            CHECK_STR_EQ(text, default_config_template);
            CHECK_EQ_INT(unlink(path), 0);
        } else {
            CHECK(access(path, F_OK) != 0);
        }
        CHECK_EQ_INT(count_prefix(dir, prefix), 0);
    }
}

TEST(backups_are_durable_monotonic_and_bounded) {
    char dir[128], path[256], body[512], backup[512];
    DIR *stream;
    struct dirent *entry;
    bool seen[7] = {false};
    int count = 0;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    config_set_backup_clock_fn(fixed_clock);
    for (int i = 0; i < 7; i++) {
        snprintf(body, sizeof(body),
                 "[settings]\ndefault_scope=\"local\"\n"
                 "[accounts.1]\nname=\"alice\"\nemail=\"a@b.com\"\n"
                 "description=\"v%d\"\n", i);
        CHECK_EQ_INT(write_private(path, body), 0);
        CHECK_EQ_INT(config_backup(path), 0);
    }
    config_set_backup_clock_fn(NULL);

    stream = opendir(dir);
    CHECK(stream != NULL);
    if (stream) {
        while ((entry = readdir(stream)) != NULL) {
            unsigned long long seconds, generation;
            unsigned int nanoseconds;
            char tail;
            if (sscanf(entry->d_name,
                       "accounts.toml.backup.%20llu.%9u.%20llu%c",
                       &seconds, &nanoseconds, &generation, &tail) != 3) {
                continue;
            }
            CHECK_EQ_INT(seconds, 1234);
            CHECK_EQ_INT(nanoseconds, 567);
            CHECK(generation < 7);
            if (generation < 7) seen[generation] = true;
            snprintf(backup, sizeof(backup), "%s/%s", dir, entry->d_name);
            CHECK(read_text(backup, body, sizeof(body)) > 0);
            char expected[32];
            snprintf(expected, sizeof(expected), "description=\"v%llu\"",
                     generation);
            CHECK(strstr(body, expected) != NULL);
            count++;
        }
        closedir(stream);
    }
    CHECK_EQ_INT(count, 5);
    CHECK(!seen[0] && !seen[1]);
    for (int i = 2; i < 7; i++) CHECK(seen[i]);
}

TEST(backup_prunes_recognized_legacy_names_in_generation_order) {
    static const char *const names[] = {
        "accounts.toml.backup.20240101_000000",
        "accounts.toml.backup.20240101_000000_1",
        "accounts.toml.backup.20240101_000000_2",
        "accounts.toml.backup.20240101_000001",
        "accounts.toml.backup.20240101_000001_1",
        "accounts.toml.backup.20240102_000000",
        "accounts.toml.backup.20240102_000000_9"
    };
    char dir[128], path[256], backup[512];
    config_backup_clock_fn previous_clock;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_private(path, one_account), 0);
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(backup, sizeof(backup), "%s/%s", dir, names[i]);
        CHECK_EQ_INT(write_private(backup, one_account), 0);
    }

    previous_clock = config_set_backup_clock_fn(fixed_clock);
    CHECK_EQ_INT(config_backup(path), 0);
    config_set_backup_clock_fn(previous_clock);

    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.backup."), 5);
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(backup, sizeof(backup), "%s/%s", dir, names[i]);
        if (i < 3) {
            CHECK(access(backup, F_OK) != 0);
        } else {
            CHECK_EQ_INT(access(backup, F_OK), 0);
        }
    }
    CHECK_EQ_INT(backup_generation_path(backup, sizeof(backup), path, 0), 0);
    CHECK_EQ_INT(access(backup, F_OK), 0);
    ts_rm_rf(dir);
}

TEST(backup_retains_malformed_legacy_near_misses_while_pruning_valid_names) {
    static const char *const valid_names[] = {
        "accounts.toml.backup.20230101_000000",
        "accounts.toml.backup.20230101_000000_1",
        "accounts.toml.backup.20230102_000000",
        "accounts.toml.backup.20230102_000000_1",
        "accounts.toml.backup.20230103_000000",
        "accounts.toml.backup.20230103_000000_1"
    };
    static const char *const malformed_names[] = {
        "accounts.toml.backup.2023010_000000",
        "accounts.toml.backup.20230101-000000",
        "accounts.toml.backup.20230101_00000",
        "accounts.toml.backup.20230101_000000_",
        "accounts.toml.backup.20230101_000000_x",
        "accounts.toml.backup.20230101_000000_18446744073709551616",
        "accounts.toml.backup.20230101_000000_123456789012345678901",
        "accounts.toml.backup.20230101_000000junk"
    };
    char dir[128], path[256], backup[512];
    config_backup_clock_fn previous_clock;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_private(path, one_account), 0);
    for (size_t i = 0;
         i < sizeof(valid_names) / sizeof(valid_names[0]); i++) {
        snprintf(backup, sizeof(backup), "%s/%s", dir, valid_names[i]);
        CHECK_EQ_INT(write_private(backup, one_account), 0);
    }
    for (size_t i = 0;
         i < sizeof(malformed_names) / sizeof(malformed_names[0]); i++) {
        snprintf(backup, sizeof(backup), "%s/%s", dir, malformed_names[i]);
        CHECK_EQ_INT(write_private(backup, "user data\n"), 0);
    }

    previous_clock = config_set_backup_clock_fn(fixed_clock);
    CHECK_EQ_INT(config_backup(path), 0);
    config_set_backup_clock_fn(previous_clock);

    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.backup."), 13);
    for (size_t i = 0;
         i < sizeof(valid_names) / sizeof(valid_names[0]); i++) {
        snprintf(backup, sizeof(backup), "%s/%s", dir, valid_names[i]);
        if (i < 2) {
            CHECK(access(backup, F_OK) != 0);
        } else {
            CHECK_EQ_INT(access(backup, F_OK), 0);
        }
    }
    for (size_t i = 0;
         i < sizeof(malformed_names) / sizeof(malformed_names[0]); i++) {
        snprintf(backup, sizeof(backup), "%s/%s", dir, malformed_names[i]);
        CHECK_EQ_INT(access(backup, F_OK), 0);
    }
    CHECK_EQ_INT(backup_generation_path(backup, sizeof(backup), path, 0), 0);
    CHECK_EQ_INT(access(backup, F_OK), 0);
    ts_rm_rf(dir);
}

TEST(backup_pruning_requires_complete_directory_enumeration) {
    char dir[128], path[256], backup[512], body[512];
    config_backup_clock_fn previous_clock;
    int backup_rc;
    int diagnostic_errno;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_private(path, one_account), 0);
    for (unsigned long long generation = 0; generation < 7; generation++) {
        CHECK_EQ_INT(backup_generation_path(backup, sizeof(backup), path,
                                            generation), 0);
        snprintf(body, sizeof(body),
                 "[settings]\ndefault_scope=\"local\"\n"
                 "[accounts.1]\nname=\"alice\"\nemail=\"a@b.com\"\n"
                 "description=\"v%llu\"\n", generation);
        CHECK_EQ_INT(write_private(backup, body), 0);
    }

    backup_readdir_scan = 0;
    backup_readdir_candidates = 0;
    backup_readdir_failed = false;
    previous_clock = config_set_backup_clock_fn(fixed_clock);
    backup_readdir_underlying = config_set_backup_readdir_fn(
        fail_second_backup_scan_mid_enumeration);
    clear_error();
    backup_rc = config_backup(path);
    diagnostic_errno = get_last_error()->system_errno;
    config_set_backup_readdir_fn(backup_readdir_underlying);
    config_set_backup_clock_fn(previous_clock);

    CHECK_EQ_INT(backup_rc, -1);
    CHECK(backup_readdir_failed);
    CHECK_EQ_INT(diagnostic_errno, EIO);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.backup."), 7);
    for (unsigned long long generation = 0; generation < 7; generation++) {
        CHECK_EQ_INT(backup_generation_path(backup, sizeof(backup), path,
                                            generation), 0);
        CHECK_EQ_INT(access(backup, F_OK), 0);
    }
    CHECK_EQ_INT(backup_generation_path(backup, sizeof(backup), path, 7), 0);
    CHECK(access(backup, F_OK) != 0);

    previous_clock = config_set_backup_clock_fn(fixed_clock);
    clear_error();
    CHECK_EQ_INT(config_backup(path), 0);
    config_set_backup_clock_fn(previous_clock);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.backup."), 5);
    for (unsigned long long generation = 0; generation < 8; generation++) {
        CHECK_EQ_INT(backup_generation_path(backup, sizeof(backup), path,
                                            generation), 0);
        if (generation < 3) {
            CHECK(access(backup, F_OK) != 0);
        } else {
            CHECK_EQ_INT(access(backup, F_OK), 0);
        }
    }
    ts_rm_rf(dir);
}

static void exercise_backup_fault(config_io_boundary_t boundary) {
    char dir[128], path[256];

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_private(path, one_account), 0);
    fault_target = boundary;
    config_set_io_fault_fn(inject_fault);
    CHECK_EQ_INT(config_backup(path), -1);
    config_set_io_fault_fn(NULL);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.backup."), 0);
}

TEST(backup_faults_abort_and_full_save_rolls_state_back) {
    char dir[128], path[256], hint[256], before_text[1024], after_text[1024];
    struct stat before, after;
    gitswitch_ctx_t ctx;

    exercise_backup_fault(CONFIG_IO_BACKUP_BEFORE_FILE_SYNC);
    exercise_backup_fault(CONFIG_IO_BACKUP_BEFORE_DIR_SYNC);
    exercise_backup_fault(CONFIG_IO_BACKUP_BEFORE_REOPEN);

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    CHECK_EQ_INT(write_private(path, two_accounts_legacy), 0);
    CHECK_EQ_INT(write_private(hint, "none\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(lstat(path, &before), 0);
    CHECK(read_text(path, before_text, sizeof(before_text)) > 0);

    /* A state rename followed by an uncertain directory sync occurs before
     * config installation; full save must restore the exact state before-image. */
    fault_target = CONFIG_IO_STATE_BEFORE_DIR_SYNC;
    config_set_io_fault_fn(inject_fault);
    CHECK_EQ_INT(config_save(&ctx, path), -1);
    config_set_io_fault_fn(NULL);
    CHECK_EQ_INT(lstat(path, &after), 0);
    CHECK(same_identity(&before, &after));
    CHECK(read_text(hint, after_text, sizeof(after_text)) > 0);
    CHECK_STR_EQ(after_text, "none\n");

    fault_target = CONFIG_IO_BACKUP_BEFORE_FILE_SYNC;
    config_set_io_fault_fn(inject_fault);
    CHECK_EQ_INT(config_save(&ctx, path), -1);
    config_set_io_fault_fn(NULL);
    CHECK_EQ_INT(lstat(path, &after), 0);
    CHECK(same_identity(&before, &after));
    CHECK(read_text(path, after_text, sizeof(after_text)) > 0);
    CHECK_STR_EQ(after_text, before_text);
    CHECK(read_text(hint, after_text, sizeof(after_text)) > 0);
    CHECK_STR_EQ(after_text, "none\n");

    CHECK_EQ_INT(config_save(&ctx, path), 0);
    CHECK(read_text(path, after_text, sizeof(after_text)) > 0);
    CHECK(strstr(after_text, "active_account") == NULL);
    CHECK(read_text(hint, after_text, sizeof(after_text)) > 0);
    CHECK_STR_EQ(after_text, "none\nactive=alice\n");
}

TEST(full_save_rollback_preserves_a_later_state_generation) {
    const config_io_boundary_t boundaries[] = {
        CONFIG_IO_STATE_BEFORE_DIR_SYNC,
        CONFIG_IO_DOCUMENT_BEFORE_RENAME
    };

    for (size_t i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); i++) {
        char dir[128], path[256], hint[256], replacement[256], text[1024];
        struct stat config_before, config_after;
        struct stat replacement_before, state_after;
        gitswitch_ctx_t ctx;

        CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
        snprintf(path, sizeof(path), "%s/accounts.toml", dir);
        snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
        snprintf(replacement, sizeof(replacement), "%s/later-state", dir);
        CHECK_EQ_INT(write_private(path, two_accounts_legacy), 0);
        CHECK_EQ_INT(write_private(hint, "none\n"), 0);
        CHECK_EQ_INT(write_private(replacement,
                                   "none\nactive=Bob\n"), 0);
        CHECK_EQ_INT(lstat(path, &config_before), 0);
        CHECK_EQ_INT(lstat(replacement, &replacement_before), 0);
        memset(&ctx, 0, sizeof(ctx));
        CHECK_EQ_INT(config_load(&ctx, path), 0);

        rollback_replace_boundary = boundaries[i];
        snprintf(rollback_replace_hint, sizeof(rollback_replace_hint),
                 "%s", hint);
        snprintf(rollback_replace_source, sizeof(rollback_replace_source),
                 "%s", replacement);
        rollback_replace_error = 0;
        config_set_io_fault_fn(replace_state_before_rollback);
        clear_error();
        CHECK_EQ_INT(config_save(&ctx, path), -1);
        config_set_io_fault_fn(NULL);

        CHECK_EQ_INT(rollback_replace_error, 0);
        CHECK(strstr(get_last_error()->message, "rollback failed") != NULL);
        CHECK_EQ_INT(lstat(path, &config_after), 0);
        CHECK(same_identity(&config_before, &config_after));
        CHECK_EQ_INT(lstat(hint, &state_after), 0);
        CHECK(same_identity(&replacement_before, &state_after));
        CHECK(read_text(hint, text, sizeof(text)) > 0);
        CHECK_STR_EQ(text, "none\nactive=Bob\n");
        CHECK_EQ_INT(count_prefix(dir, ".resume-hint.restore."), 0);
        CHECK_EQ_INT(count_prefix(dir, ".resume-hint.tmp."), 0);
    }
}

TEST(full_save_binds_and_refreshes_the_exact_source_generation) {
    char dir[128];
    char active_dir[256];
    char uncertain_dir[256];
    char path[256];
    char active_path[512];
    char uncertain_path[512];
    struct stat current;
    struct stat first_generation;
    gitswitch_ctx_t ctx;
    gitswitch_ctx_t active_ctx;
    gitswitch_ctx_t uncertain_ctx;
    gitswitch_ctx_t uncertain_before;
    bool installed = false;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(active_dir, sizeof(active_dir), "%s/active", dir);
    snprintf(uncertain_dir, sizeof(uncertain_dir), "%s/uncertain", dir);
    CHECK_EQ_INT(mkdir(active_dir, 0700), 0);
    CHECK_EQ_INT(mkdir(uncertain_dir, 0700), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(active_path, sizeof(active_path), "%s/accounts.toml", active_dir);
    snprintf(uncertain_path, sizeof(uncertain_path),
             "%s/accounts.toml", uncertain_dir);

    memset(&ctx, 0, sizeof(ctx));
    ctx.config.default_scope = GIT_SCOPE_LOCAL;
    CHECK_EQ_INT(config_save_transactional(&ctx, path, &installed), 0);
    CHECK(installed);
    CHECK(ctx.config.source_generation_valid);
    CHECK_STR_EQ(ctx.config.config_path, path);
    CHECK_EQ_INT(lstat(path, &current), 0);
    CHECK(same_identity(&ctx.config.source_generation, &current));
    first_generation = ctx.config.source_generation;

    ctx.config.default_scope = GIT_SCOPE_GLOBAL;
    installed = false;
    CHECK_EQ_INT(config_save_transactional(&ctx, path, &installed), 0);
    CHECK(installed);
    CHECK(ctx.config.source_generation_valid);
    CHECK_EQ_INT(lstat(path, &current), 0);
    CHECK(same_identity(&ctx.config.source_generation, &current));
    CHECK(!same_identity(&first_generation, &ctx.config.source_generation));

    /* Active-only publication against an absent document falls back to the
     * full first-save path. That conditional path must refresh the same
     * context so its next ordinary full save is not generationless. */
    memset(&active_ctx, 0, sizeof(active_ctx));
    active_ctx.config.default_scope = GIT_SCOPE_LOCAL;
    active_ctx.account_count = 1;
    active_ctx.accounts[0].id = 1;
    active_ctx.accounts[0].preferred_scope = GIT_SCOPE_LOCAL;
    snprintf(active_ctx.accounts[0].name,
             sizeof(active_ctx.accounts[0].name), "%s", "alice");
    snprintf(active_ctx.accounts[0].email,
             sizeof(active_ctx.accounts[0].email), "%s",
             "alice@example.com");
    snprintf(active_ctx.config.active_account,
             sizeof(active_ctx.config.active_account), "%s", "alice");
    installed = false;
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &active_ctx, active_path, &installed), 0);
    CHECK(installed);
    CHECK(active_ctx.config.source_generation_valid);
    CHECK_STR_EQ(active_ctx.config.config_path, active_path);
    active_ctx.config.default_scope = GIT_SCOPE_GLOBAL;
    CHECK_EQ_INT(config_save(&active_ctx, active_path), 0);
    CHECK_EQ_INT(lstat(active_path, &current), 0);
    CHECK(same_identity(&active_ctx.config.source_generation, &current));

    /* A post-rename directory-sync failure is installed but not a fully
     * durable success. The caller's entire context remains byte-exact and is
     * not rebound to an uncertain generation. */
    memset(&uncertain_ctx, 0, sizeof(uncertain_ctx));
    uncertain_ctx.config.default_scope = GIT_SCOPE_LOCAL;
    uncertain_before = uncertain_ctx;
    fault_target = CONFIG_IO_DOCUMENT_BEFORE_DIR_SYNC;
    config_set_io_fault_fn(inject_fault);
    installed = false;
    CHECK_EQ_INT(config_save_transactional(
                     &uncertain_ctx, uncertain_path, &installed), -1);
    config_set_io_fault_fn(NULL);
    CHECK(installed);
    CHECK(memcmp(&uncertain_ctx, &uncertain_before,
                 sizeof(uncertain_ctx)) == 0);
    CHECK_EQ_INT(access(uncertain_path, F_OK), 0);
    CHECK_EQ_INT(count_prefix(uncertain_dir, "accounts.toml.tmp."), 0);
}

TEST(self_published_witness_admits_only_exact_ctime_drift) {
    char dir[128];
    char path[256];
    char hint[256];
    char text[128];
    struct stat drifted;
    unsigned char original_first = 0U;
    gitswitch_ctx_t ctx;
    bool installed = false;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    memset(&ctx, 0, sizeof(ctx));
    ctx.config.default_scope = GIT_SCOPE_LOCAL;
    ctx.account_count = 1U;
    ctx.accounts[0].id = 1U;
    ctx.accounts[0].preferred_scope = GIT_SCOPE_LOCAL;
    snprintf(ctx.accounts[0].name, sizeof(ctx.accounts[0].name),
             "%s", "alice");
    snprintf(ctx.accounts[0].email, sizeof(ctx.accounts[0].email),
             "%s", "alice@example.com");
    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "alice");

    CHECK_EQ_INT(config_save_transactional(&ctx, path, &installed), 0);
    CHECK(installed);
    CHECK(ctx.config.source_generation_valid);
    CHECK(ctx.config.source_witness_valid);
    CHECK(ctx.config.source_witness_length ==
          (size_t)ctx.config.source_generation.st_size);
    CHECK(ctx.config.source_witness_length <=
          sizeof(ctx.config.source_witness));

    /* FreeBSD UFS can expose this exact transition after a durable rename.
     * A full-byte reproof against our self-publication witness admits it. */
    CHECK_EQ_INT(force_ctime_only_drift(
                     path, &ctx.config.source_generation, &drifted), 0);
    snprintf(document_reproof_ctime_path,
             sizeof(document_reproof_ctime_path), "%s", path);
    document_reproof_ctime_error = 0;
    config_set_io_fault_fn(drift_document_ctime_during_reproof);
    installed = false;
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, path, &installed), 0);
    config_set_io_fault_fn(NULL);
    CHECK_EQ_INT(document_reproof_ctime_error, 0);
    CHECK(!installed); /* the already-current hint is intentionally idempotent */
    CHECK(read_text(hint, text, sizeof(text)) > 0U);
    CHECK_STR_EQ(text, "none\nactive=alice\n");

    /* The same witness also authorizes a later full-model replacement. This
     * is a distinct admission path and runs again after state publication.
     * The retained bytes also cover a final UFS ctime-only step caused by the
     * verified backup read immediately before atomic replacement. */
    ctx.config.default_scope = GIT_SCOPE_GLOBAL;
    snprintf(document_prepublication_ctime_path,
             sizeof(document_prepublication_ctime_path), "%s", path);
    document_prepublication_ctime_error = 0;
    config_set_io_fault_fn(drift_document_ctime_before_publication);
    installed = false;
    CHECK_EQ_INT(config_save_transactional(&ctx, path, &installed), 0);
    config_set_io_fault_fn(NULL);
    CHECK_EQ_INT(document_prepublication_ctime_error, 0);
    CHECK(document_prepublication_ctime_path[0] == '\0');
    CHECK(installed);
    CHECK(ctx.config.source_witness_valid);
    CHECK_EQ_INT(lstat(path, &drifted), 0);
    CHECK(same_identity(&ctx.config.source_generation, &drifted));

    /* Metadata alone is insufficient: overwrite one byte on the same inode,
     * restore the original mtime, and retain the same size/mode. The exact
     * witness must reject the otherwise ctime-only source transition. */
    CHECK_EQ_INT(rewrite_first_byte_preserving_mtime(
                     path, &ctx.config.source_generation, (unsigned char)'{',
                     &original_first), 0);
    CHECK_EQ_INT(force_ctime_only_drift(
                     path, &ctx.config.source_generation, &drifted), 0);
    installed = true;
    clear_error();
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, path, &installed), -1);
    CHECK(!installed);
    CHECK(strstr(get_last_error()->message,
                 "changed since it was loaded") != NULL);
    CHECK(read_text(hint, text, sizeof(text)) > 0U);
    CHECK_STR_EQ(text, "none\nactive=alice\n");

    /* Ordinary loads retain distinct exact-read authority, not
     * self-publication authority. */
    CHECK_EQ_INT(rewrite_first_byte_preserving_mtime(
                     path, &drifted, original_first, NULL), 0);
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK(!ctx.config.source_witness_valid);
    CHECK(ctx.config.source_read_witness_valid);
    CHECK(ctx.config.source_witness_length ==
          (size_t)ctx.config.source_generation.st_size);
}

TEST(load_binds_the_post_close_source_generation) {
    char dir[128];
    char path[256];
    char hint[256];
    char text[128];
    struct stat current;
    gitswitch_ctx_t ctx;
    bool installed = false;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    CHECK_EQ_INT(write_private(path, one_account), 0);
    CHECK_EQ_INT(write_private(hint, "none\nactive=alice\n"), 0);
    memset(&ctx, 0, sizeof(ctx));

    snprintf(document_close_ctime_path,
             sizeof(document_close_ctime_path), "%s", path);
    document_close_ctime_error = 0;
    config_set_io_fault_fn(drift_document_ctime_after_close);
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    config_set_io_fault_fn(NULL);

    CHECK_EQ_INT(document_close_ctime_error, 0);
    CHECK(ctx.config.source_generation_valid);
    CHECK(!ctx.config.source_witness_valid);
    CHECK(ctx.config.source_read_witness_valid);
    CHECK_EQ_INT(lstat(path, &current), 0);
    CHECK(same_identity(&ctx.config.source_generation, &current));

    /* A later UFS directory sync may expose one more reader-induced ctime
     * step. The distinct read witness admits only its exact loaded bytes. */
    CHECK_EQ_INT(force_ctime_only_drift(
                     path, &ctx.config.source_generation, &current), 0);
    ctx.config.active_account[0] = '\0';
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, path, &installed), 0);
    CHECK(installed);
    CHECK(read_text(hint, text, sizeof(text)) > 0U);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
}

TEST(full_save_rejects_stale_absent_and_generationless_sources_early) {
    char dir[128];
    char path[256];
    char hint[256];
    char document_before[2048];
    char document_after[2048];
    char state_before[128];
    char state_after[128];
    gitswitch_ctx_t creator;
    gitswitch_ctx_t first;
    gitswitch_ctx_t second;
    gitswitch_ctx_t second_before;
    gitswitch_ctx_t generationless;
    gitswitch_ctx_t generationless_before;
    gitswitch_ctx_t disappeared;
    gitswitch_ctx_t disappeared_before;
    config_document_malloc_fn previous_malloc;
    bool installed = false;
    int backups_before;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    memset(&creator, 0, sizeof(creator));
    creator.config.default_scope = GIT_SCOPE_LOCAL;
    CHECK_EQ_INT(config_save(&creator, path), 0);

    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    CHECK_EQ_INT(config_load(&first, path), 0);
    CHECK_EQ_INT(config_load(&second, path), 0);
    first.config.default_scope = GIT_SCOPE_GLOBAL;
    CHECK_EQ_INT(config_save(&first, path), 0);
    CHECK(read_text(path, document_before, sizeof(document_before)) > 0);
    CHECK(read_text(hint, state_before, sizeof(state_before)) > 0);
    backups_before = count_prefix(dir, "accounts.toml.backup.");
    CHECK(backups_before >= 0);

    second_before = second;
    generation_document_malloc_calls = 0;
    generation_io_boundary_calls = 0;
    previous_malloc = config_set_document_malloc_fn(
        count_generation_document_malloc);
    config_set_io_fault_fn(count_generation_io_boundary);
    clear_error();
    installed = true;
    CHECK_EQ_INT(config_save_transactional(&second, path, &installed), -1);
    config_set_io_fault_fn(NULL);
    CHECK(config_set_document_malloc_fn(previous_malloc) ==
          count_generation_document_malloc);
    CHECK(!installed);
    CHECK_EQ_INT(get_last_error()->system_errno, ESTALE);
    CHECK_EQ_INT(generation_document_malloc_calls, 0);
    CHECK_EQ_INT(generation_io_boundary_calls, 0);
    CHECK(memcmp(&second, &second_before, sizeof(second)) == 0);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.backup."), backups_before);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.tmp."), 0);
    CHECK_EQ_INT(count_prefix(dir, ".resume-hint.tmp."), 0);
    CHECK(read_text(path, document_after, sizeof(document_after)) > 0);
    CHECK_STR_EQ(document_after, document_before);
    CHECK(read_text(hint, state_after, sizeof(state_after)) > 0);
    CHECK_STR_EQ(state_after, state_before);

    memset(&generationless, 0, sizeof(generationless));
    generationless.config.default_scope = GIT_SCOPE_LOCAL;
    generationless_before = generationless;
    generation_document_malloc_calls = 0;
    generation_io_boundary_calls = 0;
    previous_malloc = config_set_document_malloc_fn(
        count_generation_document_malloc);
    config_set_io_fault_fn(count_generation_io_boundary);
    clear_error();
    CHECK_EQ_INT(config_save(&generationless, path), -1);
    config_set_io_fault_fn(NULL);
    config_set_document_malloc_fn(previous_malloc);
    CHECK_EQ_INT(get_last_error()->code, ERR_FILE_IO);
    CHECK_EQ_INT(get_last_error()->system_errno, ESTALE);
    CHECK_EQ_INT(generation_document_malloc_calls, 0);
    CHECK_EQ_INT(generation_io_boundary_calls, 0);
    CHECK(memcmp(&generationless, &generationless_before,
                 sizeof(generationless)) == 0);

    disappeared = first;
    disappeared_before = disappeared;
    CHECK_EQ_INT(unlink(path), 0);
    generation_document_malloc_calls = 0;
    generation_io_boundary_calls = 0;
    previous_malloc = config_set_document_malloc_fn(
        count_generation_document_malloc);
    config_set_io_fault_fn(count_generation_io_boundary);
    clear_error();
    CHECK_EQ_INT(config_save(&disappeared, path), -1);
    config_set_io_fault_fn(NULL);
    config_set_document_malloc_fn(previous_malloc);
    CHECK_EQ_INT(get_last_error()->code, ERR_FILE_IO);
    CHECK_EQ_INT(get_last_error()->system_errno, ESTALE);
    CHECK_EQ_INT(generation_document_malloc_calls, 0);
    CHECK_EQ_INT(generation_io_boundary_calls, 0);
    CHECK(memcmp(&disappeared, &disappeared_before,
                 sizeof(disappeared)) == 0);
    CHECK_EQ_INT(access(path, F_OK), -1);
    CHECK_EQ_INT(errno, ENOENT);
    CHECK(read_text(hint, state_after, sizeof(state_after)) > 0);
    CHECK_STR_EQ(state_after, state_before);
}

static void exercise_full_save_late_generation_conflict(
    bool loaded_generation, config_io_boundary_t boundary) {
    char dir[128];
    char path[256];
    char hint[256];
    char replacement[256];
    char text[2048];
    struct stat competitor_before;
    struct stat competitor_after;
    struct stat state_before;
    struct stat state_after;
    gitswitch_ctx_t ctx;
    gitswitch_ctx_t ctx_before;
    bool installed = true;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    snprintf(replacement, sizeof(replacement), "%s/competitor.toml", dir);

    memset(&ctx, 0, sizeof(ctx));
    ctx.config.default_scope = GIT_SCOPE_LOCAL;
    if (loaded_generation) {
        CHECK_EQ_INT(write_private(path, two_accounts_legacy), 0);
        CHECK_EQ_INT(write_private(hint, "none\n"), 0);
        CHECK_EQ_INT(config_load(&ctx, path), 0);
        ctx.config.default_scope = GIT_SCOPE_GLOBAL;
        CHECK_EQ_INT(lstat(hint, &state_before), 0);
    }
    ctx_before = ctx;

    CHECK_EQ_INT(write_private(replacement, replacement_account), 0);
    CHECK_EQ_INT(lstat(replacement, &competitor_before), 0);
    snprintf(generation_swap_source, sizeof(generation_swap_source),
             "%s", path);
    snprintf(generation_swap_replacement,
             sizeof(generation_swap_replacement), "%s", replacement);
    generation_swap_boundary = boundary;
    generation_swap_error = 0;
    config_set_io_fault_fn(replace_source_at_state_publication);
    clear_error();
    CHECK_EQ_INT(config_save_transactional(&ctx, path, &installed), -1);
    config_set_io_fault_fn(NULL);

    CHECK_EQ_INT(generation_swap_error, 0);
    CHECK(generation_swap_source[0] == '\0');
    CHECK(!installed);
    CHECK_EQ_INT(get_last_error()->code, ERR_FILE_IO);
    CHECK_EQ_INT(get_last_error()->system_errno, ESTALE);
    CHECK(memcmp(&ctx, &ctx_before, sizeof(ctx)) == 0);
    CHECK_EQ_INT(lstat(path, &competitor_after), 0);
    CHECK(same_identity(&competitor_before, &competitor_after));
    CHECK(read_text(path, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, replacement_account);
    CHECK_EQ_INT(access(replacement, F_OK), -1);
    CHECK_EQ_INT(errno, ENOENT);

    if (loaded_generation) {
        CHECK_EQ_INT(lstat(hint, &state_after), 0);
        CHECK_EQ_INT((long)(state_after.st_mode & 0777), 0600);
        CHECK(read_text(hint, text, sizeof(text)) > 0);
        CHECK_STR_EQ(text, "none\n");
        if (boundary == CONFIG_IO_STATE_BEFORE_RENAME) {
            CHECK(same_identity(&state_before, &state_after));
        }
    } else {
        CHECK_EQ_INT(access(hint, F_OK), -1);
        CHECK_EQ_INT(errno, ENOENT);
    }
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.backup."), 0);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.tmp."), 0);
    CHECK_EQ_INT(count_prefix(dir, ".resume-hint.tmp."), 0);
    CHECK_EQ_INT(count_prefix(dir, ".resume-hint.restore."), 0);
}

TEST(full_save_rechecks_loaded_generation_across_state_publication) {
    const config_io_boundary_t boundaries[] = {
        CONFIG_IO_STATE_BEFORE_RENAME,
        CONFIG_IO_STATE_BEFORE_DIR_SYNC
    };

    for (size_t i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); i++) {
        exercise_full_save_late_generation_conflict(true, boundaries[i]);
    }
}

TEST(full_save_rechecks_absence_across_state_publication) {
    const config_io_boundary_t boundaries[] = {
        CONFIG_IO_STATE_BEFORE_RENAME,
        CONFIG_IO_STATE_BEFORE_DIR_SYNC
    };

    for (size_t i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); i++) {
        exercise_full_save_late_generation_conflict(false, boundaries[i]);
    }
}

TEST(full_save_rejects_post_install_in_place_rewrite_and_restores_state) {
    char dir[128];
    char path[256];
    char hint[256];
    char text[2048];
    gitswitch_ctx_t ctx;
    gitswitch_ctx_t ctx_before;
    bool installed = false;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    memset(&ctx, 0, sizeof(ctx));
    ctx.config.default_scope = GIT_SCOPE_LOCAL;
    ctx_before = ctx;

    snprintf(document_rewrite_path, sizeof(document_rewrite_path),
             "%s", path);
    document_rewrite_content = replacement_account;
    memset(&document_rewrite_before, 0, sizeof(document_rewrite_before));
    memset(&document_rewrite_after, 0, sizeof(document_rewrite_after));
    document_rewrite_error = 0;
    config_set_io_fault_fn(rewrite_document_before_directory_sync);
    clear_error();
    CHECK_EQ_INT(config_save_transactional(&ctx, path, &installed), -1);
    config_set_io_fault_fn(NULL);

    CHECK_EQ_INT(document_rewrite_error, 0);
    CHECK(document_rewrite_path[0] == '\0');
    CHECK(!installed);
    CHECK_EQ_INT(get_last_error()->code, ERR_FILE_IO);
    CHECK_EQ_INT(get_last_error()->system_errno, ESTALE);
    CHECK(memcmp(&ctx, &ctx_before, sizeof(ctx)) == 0);
    CHECK(document_rewrite_before.st_dev == document_rewrite_after.st_dev);
    CHECK(document_rewrite_before.st_ino == document_rewrite_after.st_ino);
    CHECK(read_text(path, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, replacement_account);
    CHECK_EQ_INT(access(hint, F_OK), -1);
    CHECK_EQ_INT(errno, ENOENT);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.backup."), 0);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.tmp."), 0);
    CHECK_EQ_INT(count_prefix(dir, ".resume-hint.tmp."), 0);
    CHECK_EQ_INT(count_prefix(dir, ".resume-hint.restore."), 0);
}

TEST(active_state_only_save_preserves_accounts_and_is_idempotent) {
    char dir[128], path[256], hint[256], text[1024];
    struct stat config_before, config_after, state_before, state_after;
    gitswitch_ctx_t ctx;
    gitswitch_ctx_t ctx_before;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    CHECK_EQ_INT(write_private(path, two_accounts_legacy), 0);
    CHECK_EQ_INT(write_private(hint, "none\n"), 0);
    CHECK_EQ_INT(lstat(path, &config_before), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_STR_EQ(ctx.config.active_account, "alice");
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\n"); /* loading is observational */

    ctx_before = ctx;
    CHECK_EQ_INT(config_save_active_account(&ctx, path), 0);
    CHECK(memcmp(&ctx, &ctx_before, sizeof(ctx)) == 0);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=alice\n");
    CHECK_EQ_INT(lstat(path, &config_after), 0);
    CHECK(same_identity(&config_before, &config_after));

    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "bob"); /* case-different exact match */
    ctx_before = ctx;
    CHECK_EQ_INT(config_save_active_account(&ctx, path), 0);
    CHECK(memcmp(&ctx, &ctx_before, sizeof(ctx)) == 0);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=Bob\n");
    CHECK_EQ_INT(lstat(hint, &state_before), 0);
    CHECK_EQ_INT(config_save_active_account(&ctx, path), 0);
    CHECK_EQ_INT(lstat(hint, &state_after), 0);
    CHECK(same_identity(&state_before, &state_after));
    CHECK_EQ_INT(lstat(path, &config_after), 0);
    CHECK(same_identity(&config_before, &config_after));

    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "ghost");
    CHECK_EQ_INT(config_save_active_account(&ctx, path), -1);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=Bob\n");

    ctx.config.active_account[0] = '\0';
    CHECK_EQ_INT(config_save_active_account(&ctx, path), 0);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
    CHECK_EQ_INT(lstat(path, &config_after), 0);
    CHECK(same_identity(&config_before, &config_after));
}

TEST(active_state_case_variants_normalize_and_publish_canonical_name) {
    char home[128];
    char config_parent[160];
    char config_dir[192];
    char runtime_dir[160];
    char path[256];
    char hint[256];
    char saved_home[1024];
    char saved_runtime[1024];
    char text[1024];
    const char *original_home = getenv("HOME");
    const char *original_runtime = getenv("XDG_RUNTIME_DIR");
    struct stat canonical_state;
    struct stat after_idempotent;
    gitswitch_ctx_t runtime_ctx;
    gitswitch_ctx_t readonly_ctx;
    gitswitch_ctx_t ctx_before;
    bool had_home = original_home != NULL;
    bool had_runtime = original_runtime != NULL;

    if (had_home) {
        snprintf(saved_home, sizeof(saved_home), "%s", original_home);
    }
    if (had_runtime) {
        snprintf(saved_runtime, sizeof(saved_runtime), "%s",
                 original_runtime);
    }
    CHECK_EQ_INT(private_dir(home, sizeof(home)), 0);
    snprintf(config_parent, sizeof(config_parent), "%s/.config", home);
    snprintf(config_dir, sizeof(config_dir), "%s/gitswitch", config_parent);
    snprintf(runtime_dir, sizeof(runtime_dir), "%s/runtime", home);
    CHECK_EQ_INT(mkdir(config_parent, 0700), 0);
    CHECK_EQ_INT(mkdir(config_dir, 0700), 0);
    CHECK_EQ_INT(mkdir(runtime_dir, 0700), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", config_dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", config_dir);
    CHECK_EQ_INT(write_private(path, two_accounts_legacy), 0);
    CHECK_EQ_INT(write_private(hint, "none\nactive=bob\n"), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime_dir, 1), 0);

    memset(&runtime_ctx, 0, sizeof(runtime_ctx));
    CHECK_EQ_INT(config_init(&runtime_ctx), 0);
    CHECK_STR_EQ(runtime_ctx.config.active_account, "Bob");
    CHECK(runtime_ctx.current_account != NULL);
    if (runtime_ctx.current_account) {
        CHECK_STR_EQ(runtime_ctx.current_account->name, "Bob");
    }

    memset(&readonly_ctx, 0, sizeof(readonly_ctx));
    CHECK_EQ_INT(config_init_readonly(&readonly_ctx), 0);
    CHECK_STR_EQ(readonly_ctx.config.active_account, "Bob");
    CHECK(readonly_ctx.current_account != NULL);
    if (readonly_ctx.current_account) {
        CHECK_STR_EQ(readonly_ctx.current_account->name, "Bob");
    }

    ctx_before = runtime_ctx;
    CHECK_EQ_INT(config_save_active_account(&runtime_ctx, path), 0);
    CHECK(memcmp(&runtime_ctx, &ctx_before, sizeof(runtime_ctx)) == 0);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=Bob\n");
    CHECK_EQ_INT(lstat(hint, &canonical_state), 0);
    CHECK_EQ_INT(config_save_active_account(&runtime_ctx, path), 0);
    CHECK_EQ_INT(lstat(hint, &after_idempotent), 0);
    CHECK(same_identity(&canonical_state, &after_idempotent));

    if (had_home) {
        CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("HOME"), 0);
    }
    if (had_runtime) {
        CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", saved_runtime, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("XDG_RUNTIME_DIR"), 0);
    }
}

TEST(active_state_save_is_bound_to_loaded_config_generation) {
    char dir[128], path[256], replacement[256], hint[256], text[1024];
    gitswitch_ctx_t ctx;
    bool installed = true;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(replacement, sizeof(replacement), "%s/replacement.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    CHECK_EQ_INT(write_private(path, two_accounts_legacy), 0);
    CHECK_EQ_INT(write_private(hint, "none\ninactive=v1\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "Bob");

    /* Replace the source after load with a complete, valid generation that
     * does not contain Bob. Publishing stale active state must not alter either
     * the intervening document or the prior state artifact. */
    CHECK_EQ_INT(write_private(replacement, replacement_account), 0);
    CHECK_EQ_INT(rename(replacement, path), 0);
    clear_error();
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, path, &installed), -1); /* pre-fix: 0 */
    CHECK(!installed);
    CHECK(strstr(get_last_error()->message,
                 "changed since it was loaded") != NULL);
    CHECK(read_text(path, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, replacement_account);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");

    /* Reloading records the new generation; unchanged-source publication then
     * succeeds normally. */
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "carol");
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, path, &installed), 0);
    CHECK(installed);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=carol\n");

    /* Exercise the last pre-publication generation check as well: the fault
     * callback swaps accounts.toml after the state temp is durable but before
     * its rename. The new source wins, while the prior inactive state remains. */
    CHECK_EQ_INT(write_private(replacement, two_accounts_legacy), 0);
    CHECK_EQ_INT(write_private(hint, "none\ninactive=v1\n"), 0);
    snprintf(generation_swap_source, sizeof(generation_swap_source),
             "%s", path);
    snprintf(generation_swap_replacement,
             sizeof(generation_swap_replacement), "%s", replacement);
    generation_swap_boundary = CONFIG_IO_STATE_BEFORE_RENAME;
    generation_swap_error = 0;
    installed = true;
    config_set_io_fault_fn(replace_source_at_state_publication);
    clear_error();
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, path, &installed), -1); /* pre-fix: 0 */
    config_set_io_fault_fn(NULL);
    CHECK_EQ_INT(generation_swap_error, 0);
    CHECK(!installed);
    CHECK(strstr(get_last_error()->message,
                 "changed since it was loaded") != NULL);
    CHECK(read_text(path, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, two_accounts_legacy);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
}

static void exercise_byte_identical_source_race(bool full_save) {
    char dir[128];
    char path[256];
    char hint[256];
    char replacement[256];
    char text[2048];
    struct stat replacement_before;
    struct stat source_after;
    struct stat state_before;
    struct stat state_after;
    gitswitch_ctx_t ctx;
    gitswitch_ctx_t ctx_before;
    config_io_fault_fn previous_io;
    config_metadata_test_hook_fn previous_metadata;
    bool installed = true;
    int save_result;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    snprintf(replacement, sizeof(replacement), "%s/later.toml", dir);
    CHECK_EQ_INT(write_private(path, one_account), 0);
    CHECK_EQ_INT(write_private(hint, "none\nactive=alice\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_STR_EQ(ctx.config.active_account, "alice");
    ctx_before = ctx;
    CHECK_EQ_INT(lstat(hint, &state_before), 0);

    CHECK_EQ_INT(write_private(replacement, replacement_account), 0);
    CHECK_EQ_INT(lstat(replacement, &replacement_before), 0);
    snprintf(generation_swap_source, sizeof(generation_swap_source),
             "%s", path);
    snprintf(generation_swap_replacement,
             sizeof(generation_swap_replacement), "%s", replacement);
    generation_swap_boundary = CONFIG_IO_STATE_BEFORE_DIR_SYNC;
    generation_swap_error = 0;
    document_dir_observations = 0U;
    previous_metadata = config_set_metadata_test_hook_fn(
        count_document_dir_observation);
    previous_io = config_set_io_fault_fn(
        replace_source_at_state_publication);
    clear_error();
    if (full_save) {
        save_result = config_save_transactional(&ctx, path, &installed);
    } else {
        save_result = config_save_active_account_transactional(
            &ctx, path, &installed);
    }
    config_set_io_fault_fn(previous_io);
    config_set_metadata_test_hook_fn(previous_metadata);

    /* Active-only previously returned a false success here. Full-save
     * happened to reject the source later, but only after it entered the
     * document writer; the shared final proof must stop both selectors at the
     * state commit boundary. */
    CHECK_EQ_INT(save_result, -1);
    CHECK_EQ_INT(generation_swap_error, 0);
    CHECK(generation_swap_source[0] == '\0');
    CHECK(!installed);
    CHECK_EQ_INT(get_last_error()->code, ERR_FILE_IO);
    CHECK_EQ_INT(get_last_error()->system_errno, ESTALE);
    CHECK(strstr(get_last_error()->message,
                 full_save
                     ? "refusing full-document save"
                     : "refusing active-state publication") != NULL);
    CHECK(document_dir_observations == 0U);
    CHECK(memcmp(&ctx, &ctx_before, sizeof(ctx)) == 0);

    CHECK_EQ_INT(lstat(path, &source_after), 0);
    CHECK(same_identity(&replacement_before, &source_after));
    CHECK(read_text(path, text, sizeof(text)) > 0U);
    CHECK_STR_EQ(text, replacement_account);
    CHECK_EQ_INT(access(replacement, F_OK), -1);
    CHECK_EQ_INT(errno, ENOENT);
    CHECK_EQ_INT(lstat(hint, &state_after), 0);
    CHECK(same_identity(&state_before, &state_after));
    CHECK(read_text(hint, text, sizeof(text)) > 0U);
    CHECK_STR_EQ(text, "none\nactive=alice\n");
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.backup."), 0);
    CHECK_EQ_INT(count_prefix(dir, "accounts.toml.tmp."), 0);
    CHECK_EQ_INT(count_prefix(dir, ".resume-hint.tmp."), 0);
    CHECK_EQ_INT(count_prefix(dir, ".resume-hint.restore."), 0);
    ts_rm_rf(dir);
}

TEST(byte_identical_state_retry_reproves_both_source_selectors) {
    exercise_byte_identical_source_race(false);
    exercise_byte_identical_source_race(true);
}

TEST(byte_identical_state_retry_reproves_same_inode_state) {
    char dir[128];
    char path[256];
    char hint[256];
    char text[256];
    struct stat canonical;
    struct stat after_noop;
    gitswitch_ctx_t ctx;
    gitswitch_ctx_t ctx_before;
    config_io_fault_fn previous_io;
    bool installed = true;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    CHECK_EQ_INT(write_private(path, one_account), 0);
    CHECK_EQ_INT(write_private(hint, "none\nactive=alice\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_STR_EQ(ctx.config.active_account, "alice");
    ctx_before = ctx;

    CHECK_EQ_INT((long)strlen("none\nactive=alice\n"),
                 (long)strlen("none\nactive=ALICE\n"));
    snprintf(noop_state_rewrite_hint,
             sizeof(noop_state_rewrite_hint), "%s", hint);
    snprintf(noop_state_rewrite_content,
             sizeof(noop_state_rewrite_content), "%s",
             "none\nactive=ALICE\n");
    memset(&noop_state_rewrite_before, 0,
           sizeof(noop_state_rewrite_before));
    memset(&noop_state_rewrite_after, 0,
           sizeof(noop_state_rewrite_after));
    noop_state_rewrite_error = 0;
    previous_io = config_set_io_fault_fn(
        rewrite_noop_state_before_directory_sync);
    clear_error();
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, path, &installed), -1); /* pre-fix: 0 */
    config_set_io_fault_fn(previous_io);

    CHECK_EQ_INT(noop_state_rewrite_error, 0);
    CHECK(noop_state_rewrite_hint[0] == '\0');
    CHECK(!installed);
    CHECK_EQ_INT(get_last_error()->code, ERR_FILE_IO);
    CHECK_EQ_INT(get_last_error()->system_errno, ESTALE);
    CHECK(strstr(get_last_error()->message,
                 "Resume hint changed before update") != NULL);
    CHECK(memcmp(&ctx, &ctx_before, sizeof(ctx)) == 0);
    CHECK(noop_state_rewrite_before.st_dev ==
          noop_state_rewrite_after.st_dev);
    CHECK(noop_state_rewrite_before.st_ino ==
          noop_state_rewrite_after.st_ino);
    CHECK_EQ_INT(noop_state_rewrite_before.st_size,
                 noop_state_rewrite_after.st_size);
    CHECK(same_mtime(&noop_state_rewrite_before,
                     &noop_state_rewrite_after));
    CHECK(!same_ctime(&noop_state_rewrite_before,
                      &noop_state_rewrite_after));
    CHECK(read_text(hint, text, sizeof(text)) > 0U);
    CHECK_STR_EQ(text, "none\nactive=ALICE\n");
    CHECK_EQ_INT(count_prefix(dir, ".resume-hint.tmp."), 0);
    CHECK_EQ_INT(count_prefix(dir, ".resume-hint.restore."), 0);

    installed = false;
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, path, &installed), 0);
    CHECK(installed);
    CHECK(read_text(hint, text, sizeof(text)) > 0U);
    CHECK_STR_EQ(text, "none\nactive=alice\n");
    CHECK_EQ_INT(lstat(hint, &canonical), 0);

    installed = true;
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, path, &installed), 0);
    CHECK(!installed);
    CHECK_EQ_INT(lstat(hint, &after_noop), 0);
    CHECK(same_identity(&canonical, &after_noop));
    CHECK_EQ_INT(count_prefix(dir, ".resume-hint.tmp."), 0);
    CHECK_EQ_INT(count_prefix(dir, ".resume-hint.restore."), 0);
    ts_rm_rf(dir);
}

TEST(active_state_publish_reproves_exact_before_image_after_hook) {
    char dir[128];
    char path[256];
    char hint[256];
    char text[128];
    struct stat before;
    struct stat after;
    gitswitch_ctx_t ctx;
    gitswitch_ctx_t ctx_before;
    bool installed = true;
    int fds_before;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    CHECK_EQ_INT(write_private(path, one_account), 0);
    CHECK_EQ_INT(write_private(hint, "none\nactive=alice\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_STR_EQ(ctx.config.active_account, "alice");
    ctx.config.active_account[0] = '\0';
    ctx_before = ctx;
    CHECK_EQ_INT(lstat(hint, &before), 0);
    fds_before = count_open_fds();

    CHECK_EQ_INT((long)strlen("none\nactive=alice\n"),
                 (long)strlen("none\nactive=ALICE\n"));
    snprintf(state_rewrite_hint, sizeof(state_rewrite_hint), "%s", hint);
    snprintf(state_rewrite_content, sizeof(state_rewrite_content), "%s",
             "none\nactive=ALICE\n");
    state_rewrite_error = 0;
    state_rewrite_expected = before;
    state_rewrite_restore_times = true;
    config_set_io_fault_fn(rewrite_state_before_publication);
    clear_error();
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, path, &installed), -1);
    config_set_io_fault_fn(NULL);

    CHECK_EQ_INT(state_rewrite_error, 0);
    CHECK(!installed);
    CHECK_EQ_INT(get_last_error()->code, ERR_FILE_IO);
    CHECK_EQ_INT(get_last_error()->system_errno, ESTALE);
    CHECK(strstr(get_last_error()->message,
                 "Resume hint changed before update") != NULL);
    CHECK(memcmp(&ctx, &ctx_before, sizeof(ctx)) == 0);
    CHECK_EQ_INT(lstat(hint, &after), 0);
    CHECK(before.st_dev == after.st_dev && before.st_ino == after.st_ino);
    CHECK_EQ_INT(before.st_size, after.st_size);
    CHECK(same_mtime(&before, &after));
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=ALICE\n");
    CHECK_EQ_INT(count_prefix(dir, ".resume-hint.tmp."), 0);
    CHECK_EQ_INT(count_open_fds(), fds_before);

    /* The rejected writer owns no residue; the same still-loaded account
     * generation can retry against the later state and replace it normally. */
    installed = false;
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, path, &installed), 0);
    CHECK(installed);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
    CHECK_EQ_INT(count_prefix(dir, ".resume-hint.tmp."), 0);
}

TEST(active_state_exact_witness_admits_ctime_only_drift) {
    char dir[128];
    char path[256];
    char hint[256];
    char text[128];
    gitswitch_ctx_t ctx;
    bool installed = false;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    CHECK_EQ_INT(write_private(path, one_account), 0);
    CHECK_EQ_INT(write_private(hint, "none\nactive=alice\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    ctx.config.active_account[0] = '\0';

    snprintf(state_ctime_drift_hint, sizeof(state_ctime_drift_hint),
             "%s", hint);
    state_ctime_drift_error = 0;
    config_set_io_fault_fn(drift_state_ctime_before_publication);
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, path, &installed), 0);
    config_set_io_fault_fn(NULL);

    CHECK_EQ_INT(state_ctime_drift_error, 0);
    CHECK(installed);
    CHECK(read_text(hint, text, sizeof(text)) > 0U);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
    CHECK_EQ_INT(count_prefix(dir, ".resume-hint.tmp."), 0);
}

TEST(historical_active_state_migrates_without_reset_resurrection) {
    char dir[128], path[256], hint[256], text[1024];
    struct stat state_before, state_after;
    gitswitch_ctx_t ctx;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    CHECK_EQ_INT(write_private(path, two_accounts_legacy), 0);

    /* The oldest active-state representation was accounts.toml alone. Loading
     * remains observational; the next state save performs the migration. */
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_STR_EQ(ctx.config.active_account, "alice");
    CHECK(access(hint, F_OK) != 0);
    CHECK_EQ_INT(config_save_active_account(&ctx, path), 0);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=alice\n");

    /* The first resume marker was a zero-byte file. It also migrates from the
     * legacy key and is replaced with the consolidated two-line record. */
    CHECK_EQ_INT(write_private(hint, ""), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_STR_EQ(ctx.config.active_account, "alice");
    CHECK_EQ_INT(lstat(hint, &state_before), 0);
    CHECK_EQ_INT(state_before.st_size, 0);
    CHECK_EQ_INT(config_save_active_account(&ctx, path), 0);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=alice\n");

    /* Reset cannot delete the only fact distinguishing reset from a historical
     * active-only file. Persist an authoritative tombstone, then prove the
     * still-byte-identical legacy key is not resurrected on reload. */
    ctx.config.active_account[0] = '\0';
    CHECK_EQ_INT(config_save_active_account(&ctx, path), 0);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
    CHECK(read_text(path, text, sizeof(text)) > 0);
    CHECK(strstr(text, "active_account = \"alice\"") != NULL);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_STR_EQ(ctx.config.active_account, "");

    CHECK_EQ_INT(lstat(hint, &state_before), 0);
    CHECK_EQ_INT(config_save_active_account(&ctx, path), 0);
    CHECK_EQ_INT(lstat(hint, &state_after), 0);
    CHECK(same_identity(&state_before, &state_after));
}

TEST(one_line_active_state_mismatch_degrades_without_observational_rewrite) {
    char dir[128], path[256], hint[256], text[1024];
    gitswitch_ctx_t ctx;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    CHECK_EQ_INT(write_private(path, two_accounts_legacy), 0);
    CHECK_EQ_INT(write_private(hint, "ssh\n"), 0);

    /* A one-line marker carries a real runtime-needs claim even though its
     * account identity still migrates from settings.active_account. Treat a
     * mismatch like the equivalent two-line crash window, but keep loading
     * observational until a serialized state save owns the rewrite. */
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_STR_EQ(ctx.config.active_account, "");
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "ssh\n");

    CHECK_EQ_INT(config_save_active_account(&ctx, path), 0);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
}

TEST(active_state_rejects_corruption_and_crash_mismatches) {
    char dir[128], path[256], hint[256], text[1024];
    gitswitch_ctx_t ctx;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    CHECK_EQ_INT(write_private(path, one_account), 0);

    CHECK_EQ_INT(write_private(hint, "none\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), -1);
    CHECK(strstr(get_last_error()->message,
                 "has no settings.active_account migration source") != NULL);

    CHECK_EQ_INT(write_private(hint, "garbage\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), -1);
    CHECK_EQ_INT(write_private(hint, "none\nactive=bad/name\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), -1);
    /* AR-12 M3: a stale needs token (hand edit or gitswitch's own crash
     * window between state install and document rename) is repairable
     * staleness: degrade to inactive without mutating the artifact from an
     * unlocked read, instead of hard-failing every command. */
    CHECK_EQ_INT(write_private(hint, "ssh\nactive=alice\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_STR_EQ(ctx.config.active_account, "");
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "ssh\nactive=alice\n");

    /* State-first active removal crash: old accounts remain, but resume is
     * safely inactive because the authoritative state artifact is absent. */
    CHECK_EQ_INT(unlink(hint), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_STR_EQ(ctx.config.active_account, "");

    /* Rename/config-first mismatch: never apply the stale identity and never
     * mutate it from an unlocked read. */
    CHECK_EQ_INT(write_private(hint, "none\nactive=renamed\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_STR_EQ(ctx.config.active_account, "");
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=renamed\n");
    CHECK_EQ_INT(config_save_active_account(&ctx, path), 0);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
}

TEST(active_state_faults_report_install_boundary_and_do_not_leak_fds) {
    const config_io_boundary_t pre_install[] = {
        CONFIG_IO_STATE_AFTER_TEMP,
        CONFIG_IO_STATE_AFTER_WRITE,
        CONFIG_IO_STATE_BEFORE_FILE_SYNC,
        CONFIG_IO_STATE_BEFORE_CLOSE,
        CONFIG_IO_STATE_BEFORE_RENAME
    };
    char dir[128], path[256], hint[256], text[1024];
    gitswitch_ctx_t ctx;
    bool installed = true;
    int before;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    CHECK_EQ_INT(write_private(path, two_accounts_legacy), 0);
    CHECK_EQ_INT(write_private(hint, "none\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);

    config_set_io_fault_fn(inject_fault);
    before = count_open_fds();
    for (size_t i = 0; i < sizeof(pre_install) / sizeof(pre_install[0]); i++) {
        fault_target = pre_install[i];
        CHECK_EQ_INT(config_save_active_account_transactional(
                         &ctx, path, &installed), -1);
        CHECK(!installed);
        CHECK(read_text(hint, text, sizeof(text)) > 0);
        CHECK_STR_EQ(text, "none\n");
        CHECK_EQ_INT(count_prefix(dir, ".resume-hint.tmp."), 0);
    }

    fault_target = CONFIG_IO_STATE_BEFORE_CLOSE;
    for (int i = 0; i < 32; i++) {
        CHECK_EQ_INT(config_save_active_account_transactional(
                         &ctx, path, &installed), -1);
        CHECK(!installed);
    }
    CHECK_EQ_INT(count_open_fds(), before);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\n");
    CHECK_EQ_INT(count_prefix(dir, ".resume-hint.tmp."), 0);

    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "Bob");
    fault_target = CONFIG_IO_STATE_BEFORE_DIR_SYNC;
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, path, &installed), -1);
    CHECK(installed);
    config_set_io_fault_fn(NULL);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=Bob\n");
}

TEST(active_state_registration_failure_is_atomic_and_retryable) {
    char scratch[TEST_SCRATCH_PROBE_MAX][TEST_SCRATCH_PATH_SIZE];
    char dir[128], path[256], hint[256], text[1024];
    gitswitch_ctx_t ctx;
    size_t registered;
    bool installed = true;
    int before;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    CHECK_EQ_INT(write_private(path, two_accounts_legacy), 0);
    CHECK_EQ_INT(write_private(hint, "none\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);

    before = test_open_fd_count();
    registered = test_scratch_fill(scratch, "state-full");
    CHECK(registered > 0 && registered < TEST_SCRATCH_PROBE_MAX);
    clear_error();
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, path, &installed), -1);
    CHECK(!installed);
    CHECK(strstr(get_last_error()->message, "register") != NULL);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\n");
    CHECK_EQ_INT(count_prefix(dir, ".resume-hint.tmp."), 0);

    test_scratch_release(scratch, registered);
    CHECK_EQ_INT(test_open_fd_count(), before);
    clear_error();
    CHECK_EQ_INT(config_save_active_account_transactional(
                     &ctx, path, &installed), 0);
    CHECK(installed);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=alice\n");
    CHECK_EQ_INT(count_prefix(dir, ".resume-hint.tmp."), 0);
}

TEST_MAIN_BEGIN()
    RUN_TEST(schema_rejects_lossy_types_and_dependent_keys);
    RUN_TEST(malformed_gpg_selector_skips_only_its_account_and_blocks_rewrite);
    RUN_TEST(default_create_fault_matrix_is_atomic_and_closes_fds);
    RUN_TEST(default_create_signal_death_is_truthful_at_every_boundary);
    RUN_TEST(backups_are_durable_monotonic_and_bounded);
    RUN_TEST(backup_prunes_recognized_legacy_names_in_generation_order);
    RUN_TEST(backup_retains_malformed_legacy_near_misses_while_pruning_valid_names);
    RUN_TEST(backup_pruning_requires_complete_directory_enumeration);
    RUN_TEST(backup_faults_abort_and_full_save_rolls_state_back);
    RUN_TEST(full_save_rollback_preserves_a_later_state_generation);
    RUN_TEST(full_save_binds_and_refreshes_the_exact_source_generation);
    RUN_TEST(self_published_witness_admits_only_exact_ctime_drift);
    RUN_TEST(load_binds_the_post_close_source_generation);
    RUN_TEST(full_save_rejects_stale_absent_and_generationless_sources_early);
    RUN_TEST(full_save_rechecks_loaded_generation_across_state_publication);
    RUN_TEST(full_save_rechecks_absence_across_state_publication);
    RUN_TEST(full_save_rejects_post_install_in_place_rewrite_and_restores_state);
    RUN_TEST(active_state_only_save_preserves_accounts_and_is_idempotent);
    RUN_TEST(active_state_case_variants_normalize_and_publish_canonical_name);
    RUN_TEST(active_state_save_is_bound_to_loaded_config_generation);
    RUN_TEST(byte_identical_state_retry_reproves_both_source_selectors);
    RUN_TEST(byte_identical_state_retry_reproves_same_inode_state);
    RUN_TEST(active_state_publish_reproves_exact_before_image_after_hook);
    RUN_TEST(active_state_exact_witness_admits_ctime_only_drift);
    RUN_TEST(historical_active_state_migrates_without_reset_resurrection);
    RUN_TEST(one_line_active_state_mismatch_degrades_without_observational_rewrite);
    RUN_TEST(active_state_rejects_corruption_and_crash_mismatches);
    RUN_TEST(active_state_faults_report_install_boundary_and_do_not_leak_fds);
    RUN_TEST(active_state_registration_failure_is_atomic_and_retryable);
TEST_MAIN_END()
