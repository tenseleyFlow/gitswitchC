/* AR-07 T12: lossless schema admission and crash-truthful persistence. */
#include "test.h"
#include "config.h"
#include "error.h"
#include "signals.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <sys/wait.h>

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
static config_io_boundary_t rollback_replace_boundary;
static char rollback_replace_hint[256];
static char rollback_replace_source[256];
static int rollback_replace_error;

static bool inject_fault(config_io_boundary_t boundary) {
    return boundary == fault_target;
}

static bool replace_source_at_state_publication(
    config_io_boundary_t boundary) {
    if (boundary == CONFIG_IO_STATE_BEFORE_RENAME &&
        generation_swap_source[0] != '\0') {
        if (rename(generation_swap_replacement,
                   generation_swap_source) != 0) {
            generation_swap_error = errno ? errno : EIO;
        }
        generation_swap_source[0] = '\0';
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
                      "ssh_host=\"github.com\"\n",
                      "ssh_host requires a non-empty ssh_key");
    expect_load_error("[settings]\ndefault_scope=\"local\"\n"
                      "[accounts.1]\nname=\"alice\"\nemail=\"a@b.com\"\n"
                      "ssh_key=\"\"\nssh_hostname=\"github.com\"\n",
                      "ssh_hostname requires a non-empty ssh_key");
    expect_load_error("[settings]\ndefault_scope=\"local\"\n"
                      "[accounts.1]\nname=\"alice\"\nemail=\"a@b.com\"\n"
                      "gpg_key=\"\"\ngpg_signing_enabled=false\n",
                      "gpg_signing_enabled requires a non-empty gpg_key");
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

TEST(active_state_only_save_preserves_accounts_and_is_idempotent) {
    char dir[128], path[256], hint[256], text[1024];
    struct stat config_before, config_after, state_before, state_after;
    gitswitch_ctx_t ctx;

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

    CHECK_EQ_INT(config_save_active_account(&ctx, path), 0);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=alice\n");
    CHECK_EQ_INT(lstat(path, &config_after), 0);
    CHECK(same_identity(&config_before, &config_after));

    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "bob"); /* case-different exact match */
    CHECK_EQ_INT(config_save_active_account(&ctx, path), 0);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\nactive=bob\n");
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
    CHECK_STR_EQ(text, "none\nactive=bob\n");

    ctx.config.active_account[0] = '\0';
    CHECK_EQ_INT(config_save_active_account(&ctx, path), 0);
    CHECK(read_text(hint, text, sizeof(text)) > 0);
    CHECK_STR_EQ(text, "none\ninactive=v1\n");
    CHECK_EQ_INT(lstat(path, &config_after), 0);
    CHECK(same_identity(&config_before, &config_after));
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

TEST(active_state_rejects_corruption_and_crash_mismatches) {
    char dir[128], path[256], hint[256], text[1024];
    gitswitch_ctx_t ctx;

    CHECK_EQ_INT(private_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    CHECK_EQ_INT(write_private(path, one_account), 0);

    CHECK_EQ_INT(write_private(hint, "garbage\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), -1);
    CHECK_EQ_INT(write_private(hint, "none\nactive=bad/name\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), -1);
    CHECK_EQ_INT(write_private(hint, "ssh\nactive=alice\n"), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), -1); /* edit changed runtime needs */

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

TEST_MAIN_BEGIN()
    RUN_TEST(schema_rejects_lossy_types_and_dependent_keys);
    RUN_TEST(default_create_fault_matrix_is_atomic_and_closes_fds);
    RUN_TEST(default_create_signal_death_is_truthful_at_every_boundary);
    RUN_TEST(backups_are_durable_monotonic_and_bounded);
    RUN_TEST(backup_faults_abort_and_full_save_rolls_state_back);
    RUN_TEST(full_save_rollback_preserves_a_later_state_generation);
    RUN_TEST(active_state_only_save_preserves_accounts_and_is_idempotent);
    RUN_TEST(active_state_save_is_bound_to_loaded_config_generation);
    RUN_TEST(historical_active_state_migrates_without_reset_resurrection);
    RUN_TEST(active_state_rejects_corruption_and_crash_mismatches);
    RUN_TEST(active_state_faults_report_install_boundary_and_do_not_leak_fds);
TEST_MAIN_END()
