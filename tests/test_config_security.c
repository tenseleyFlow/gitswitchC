/* Security regression tests for the config reader/writer:
 * - cfg-symlink-01/02: a symlinked accounts.toml (or backup destination) is
 *   refused on both the read and the write path; normal regular-file
 *   operation is unchanged.
 * - int-id-01/02: account ids are canonical decimals; out-of-range or
 *   non-canonical spellings never wrap/alias onto another account.
 * - tty-escape: terminal control bytes in description/name are stripped or
 *   rejected at config load / account validation, never handed to display. */
#include "test.h"
#include "gitswitch.h"
#include "accounts.h"
#include "config.h"
#include "toml_parser.h"
#include "signals.h"
#include "error.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dirent.h>
#include <pwd.h>

/* Minimal valid config: one account, no key material (so no key-permission
 * checks fire in validate_account_security). */
static const char *valid_config =
    "[settings]\n"
    "default_scope = \"local\"\n"
    "\n"
    "[accounts.1]\n"
    "name = \"alice\"\n"
    "email = \"a@b.com\"\n"
    "description = \"day job\"\n";

/* Create a fresh 0700 scratch directory for one test. */
static int make_scratch_dir(char *dir, size_t size) {
    snprintf(dir, size, "/tmp/gswcfgtest.XXXXXX");
    if (!ts_mkdtemp(dir) || ts_canonicalize_dir_path(dir, size) != 0) {
        return -1;
    }
    return 0;
}

/* Write content to path with the 0600 mode the loader requires. */
static int write_config(const char *path, const char *content, size_t len) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    if (fwrite(content, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return chmod(path, 0600);
}

static size_t slurp(const char *path, char *buf, size_t size) {
    FILE *f = fopen(path, "r");
    size_t n;
    if (!f) return 0;
    n = fread(buf, 1, size - 1, f);
    fclose(f);
    buf[n] = '\0';
    return n;
}

static int join_path(char *dest, size_t size, const char *base,
                     const char *suffix) {
    size_t base_len = strlen(base);
    size_t suffix_len = strlen(suffix);

    if (base_len >= size || suffix_len > size - base_len - 1) {
        return -1;
    }
    memcpy(dest, base, base_len);
    memcpy(dest + base_len, suffix, suffix_len + 1);
    return 0;
}

static void save_home_env(char *buf, size_t size) {
    const char *home = getenv("HOME");
    snprintf(buf, size, "%s", home ? home : "");
}

static void restore_home_env(const char *saved) {
    if (saved[0] != '\0') setenv("HOME", saved, 1);
    else unsetenv("HOME");
}

static void fill_account(account_t *a, uint32_t id, const char *name,
                         const char *email, const char *desc) {
    memset(a, 0, sizeof(*a));
    a->id = id;
    strncpy(a->name, name, sizeof(a->name) - 1);
    strncpy(a->email, email, sizeof(a->email) - 1);
    strncpy(a->description, desc, sizeof(a->description) - 1);
    a->preferred_scope = GIT_SCOPE_LOCAL;
}

typedef enum {
    INVALID_SSH_ENABLED_WITHOUT_KEY = 0,
    INVALID_SSH_DISABLED_WITH_KEY,
    INVALID_SSH_DISABLED_WITH_ALIAS,
    INVALID_SSH_DISABLED_WITH_HOSTNAME,
    INVALID_GPG_ENABLED_WITHOUT_KEY,
    INVALID_GPG_DISABLED_WITH_KEY,
    INVALID_GPG_DISABLED_WITH_SIGNING
} invalid_account_model_t;

static void fill_invalid_account_model(account_t *account,
                                       invalid_account_model_t invalid,
                                       const char *ssh_key) {
    fill_account(account, 1, "invalid", "invalid@example.com", "invalid");
    switch (invalid) {
        case INVALID_SSH_ENABLED_WITHOUT_KEY:
            account->ssh_enabled = true;
            break;
        case INVALID_SSH_DISABLED_WITH_KEY:
            strncpy(account->ssh_key_path, ssh_key,
                    sizeof(account->ssh_key_path) - 1U);
            break;
        case INVALID_SSH_DISABLED_WITH_ALIAS:
            strncpy(account->ssh_host_alias, "github-work",
                    sizeof(account->ssh_host_alias) - 1U);
            break;
        case INVALID_SSH_DISABLED_WITH_HOSTNAME:
            strncpy(account->ssh_hostname, "github.com",
                    sizeof(account->ssh_hostname) - 1U);
            break;
        case INVALID_GPG_ENABLED_WITHOUT_KEY:
            account->gpg_enabled = true;
            break;
        case INVALID_GPG_DISABLED_WITH_KEY:
            strncpy(account->gpg_key_id, "ABCDEF0123456789",
                    sizeof(account->gpg_key_id) - 1U);
            break;
        case INVALID_GPG_DISABLED_WITH_SIGNING:
            account->gpg_signing_enabled = true;
            break;
        default:
            break;
    }
}

static void seed_three_accounts(gitswitch_ctx_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->config.default_scope = GIT_SCOPE_LOCAL;
    fill_account(&ctx->accounts[0], 1, "before", "before@x.com", "before");
    fill_account(&ctx->accounts[1], 2, "current-old", "current@x.com", "current");
    fill_account(&ctx->accounts[2], 3, "after", "after@x.com", "after");
    ctx->account_count = 3;
    ctx->current_account = &ctx->accounts[1];
}

static void seed_reload_sentinel(gitswitch_ctx_t *ctx) {
    seed_three_accounts(ctx);
    ctx->config.default_scope = GIT_SCOPE_GLOBAL;
    snprintf(ctx->config.config_path, sizeof(ctx->config.config_path),
             "/sentinel/original.toml");
    snprintf(ctx->config.active_account, sizeof(ctx->config.active_account),
             "current-old");
    ctx->config.verbose = true;
    ctx->config.dry_run = true;
    ctx->config.color_output = true;
    ctx->config.force_global = true;
    ctx->config.force_local = false;
    ctx->config.resuming = true;
    ctx->config.assume_yes = true;
    ctx->config.defer_signal_cleanup = true;
    ctx->accounts_skipped_on_load = 71;
    ctx->unknown_sections_on_load = 72;
    ctx->unknown_keys_on_load = 73;
}

static bool current_pointer_is_valid(const gitswitch_ctx_t *ctx) {
    if (!ctx->current_account) return true;
    for (size_t i = 0; i < ctx->account_count; i++) {
        if (ctx->current_account == &ctx->accounts[i]) return true;
    }
    return false;
}

static int install_live_current_socket(const char *runtime,
                                       const char *account_name) {
    char dir[256];
    char current[320];
    char lock_path[320];
    char socket_path[320];
    struct sockaddr_un address;
    int listener;
    int lock_fd;

    if (snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", runtime) >=
        (int)sizeof(dir) ||
        (mkdir(dir, 0700) != 0 && errno != EEXIST) || chmod(dir, 0700) != 0 ||
        snprintf(lock_path, sizeof(lock_path), "%s/.lock", dir) >=
            (int)sizeof(lock_path) ||
        snprintf(socket_path, sizeof(socket_path), "%s/ssh-agent.%s.sock",
                 dir, account_name) >= (int)sizeof(socket_path) ||
        strlen(socket_path) >= sizeof(address.sun_path)) {
        return -1;
    }

    /* Read-only current-account discovery intentionally refuses to create or
     * repair the manager lock.  A live-runtime fixture must therefore model
     * the writer-established private lock that protects current.sock. */
    lock_fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0) return -1;
    if (fchmod(lock_fd, 0600) != 0) {
        int saved_errno = errno;
        close(lock_fd);
        errno = saved_errno;
        return -1;
    }
    if (close(lock_fd) != 0) return -1;

    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0) return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, socket_path, strlen(socket_path) + 1U);
    unlink(socket_path);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        chmod(socket_path, 0600) != 0 || listen(listener, 4) != 0 ||
        snprintf(current, sizeof(current), "%s/current.sock", dir) >=
            (int)sizeof(current)) {
        close(listener);
        unlink(socket_path);
        return -1;
    }
    unlink(current);
    if (symlink(socket_path, current) != 0) {
        close(listener);
        unlink(socket_path);
        return -1;
    }
    return listener;
}

static size_t count_occurrences(const char *haystack, const char *needle) {
    size_t count = 0;
    size_t needle_len = strlen(needle);

    if (needle_len == 0) return 0;
    while ((haystack = strstr(haystack, needle)) != NULL) {
        count++;
        haystack += needle_len;
    }
    return count;
}

static const char *growth_hook_path;
static bool growth_hook_ran;

static bool append_after_prefix_read(config_io_boundary_t boundary) {
    static const char appended_account[] =
        "\n[accounts.2]\n"
        "name = \"bob\"\n"
        "email = \"b@b.com\"\n";
    int fd;
    size_t total = 0;

    if (boundary != CONFIG_IO_DOCUMENT_AFTER_PREFIX_READ || growth_hook_ran) {
        return false;
    }
    growth_hook_ran = true;
    fd = open(growth_hook_path, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0) return false;
    while (total < sizeof(appended_account) - 1U) {
        ssize_t written = write(fd, appended_account + total,
                                sizeof(appended_account) - 1U - total);
        if (written > 0) {
            total += (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    (void)fsync(fd);
    close(fd);
    return false;
}

/* ---- cfg-symlink-01/02: read path ---- */

TEST(load_accepts_regular_file) {
    char dir[128], path[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, valid_config, strlen(valid_config)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    if (ctx.account_count == 1) {
        CHECK_STR_EQ(ctx.accounts[0].name, "alice");
        CHECK_EQ_INT(ctx.accounts[0].id, 1);
    }
}

TEST(load_rejects_file_growth_after_prefix_read) {
    char dir[128], path[256], contents[1024];
    gitswitch_ctx_t ctx;

    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, valid_config, strlen(valid_config)), 0);

    growth_hook_path = path;
    growth_hook_ran = false;
    config_set_io_fault_fn(append_after_prefix_read);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), -1); /* pre-fix: accepted alice only */
    config_set_io_fault_fn(NULL);

    CHECK(growth_hook_ran);
    CHECK(slurp(path, contents, sizeof(contents)) > 0);
    CHECK(strstr(contents, "[accounts.2]") != NULL);
}

TEST(system_scope_is_rejected_before_admission_or_persistence) {
    char dir[128], account_dir[256];
    char default_path[512], account_path[512];
    char default_hint[512], account_hint[512];
    gitswitch_ctx_t ctx;
    account_t local, system, before;

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&system, 1, "alice", "a@b.com", "day job");
    system.preferred_scope = GIT_SCOPE_SYSTEM;
    CHECK_EQ_INT(config_add_account(&ctx, &system), -1); /* pre-fix: 0 */
    CHECK_EQ_INT(ctx.account_count, 0);

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&local, 1, "alice", "a@b.com", "day job");
    CHECK_EQ_INT(config_add_account(&ctx, &local), 0);
    before = ctx.accounts[0];
    CHECK_EQ_INT(config_update_account(&ctx, &system), -1); /* pre-fix: 0 */
    CHECK(memcmp(&ctx.accounts[0], &before, sizeof(before)) == 0);

    ctx.config.default_scope = GIT_SCOPE_SYSTEM;
    CHECK_EQ_INT(config_validate(&ctx), -1); /* pre-fix: 0 */
    ctx.config.default_scope = GIT_SCOPE_LOCAL;
    ctx.accounts[0] = system;
    CHECK_EQ_INT(config_validate(&ctx), -1); /* pre-fix: 0 */

    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    CHECK_EQ_INT(join_path(default_path, sizeof(default_path), dir,
                           "/default.toml"), 0);
    CHECK_EQ_INT(join_path(default_hint, sizeof(default_hint), dir,
                           "/.resume-hint"), 0);

    memset(&ctx, 0, sizeof(ctx));
    ctx.config.default_scope = GIT_SCOPE_SYSTEM;
    CHECK_EQ_INT(config_save(&ctx, default_path), -1); /* pre-fix: 0 */
    CHECK(access(default_path, F_OK) != 0);
    CHECK(access(default_hint, F_OK) != 0);

    /* Use a separate private directory so an accidental resume-hint write by
     * the first save cannot mask whether the account-scope save was pure. */
    CHECK_EQ_INT(join_path(account_dir, sizeof(account_dir), dir,
                           "/account-dir"), 0);
    CHECK_EQ_INT(mkdir(account_dir, 0700), 0);
    CHECK_EQ_INT(join_path(account_path, sizeof(account_path), account_dir,
                           "/account.toml"), 0);
    CHECK_EQ_INT(join_path(account_hint, sizeof(account_hint), account_dir,
                           "/.resume-hint"), 0);
    memset(&ctx, 0, sizeof(ctx));
    ctx.config.default_scope = GIT_SCOPE_LOCAL;
    ctx.accounts[0] = system;
    ctx.account_count = 1;
    CHECK_EQ_INT(config_save(&ctx, account_path), -1); /* pre-fix: 0 */
    CHECK(access(account_path, F_OK) != 0);
    CHECK(access(account_hint, F_OK) != 0);
}

TEST(zero_account_id_is_rejected_before_mutation_or_persistence) {
    char dir[128], path[512], hint[512];
    gitswitch_ctx_t ctx;
    account_t zero, changed, before;

    fill_account(&zero, 0, "zero", "zero@x.com", "zero");
    memset(&ctx, 0, sizeof(ctx));
    ctx.config.default_scope = GIT_SCOPE_LOCAL;
    CHECK_EQ_INT(config_add_account(&ctx, &zero), -1); /* pre-fix: 0 */
    CHECK_EQ_INT(ctx.account_count, 0);

    memset(&ctx, 0, sizeof(ctx));
    ctx.config.default_scope = GIT_SCOPE_LOCAL;
    ctx.accounts[0] = zero;
    ctx.account_count = 1;
    before = ctx.accounts[0];
    changed = zero;
    snprintf(changed.name, sizeof(changed.name), "zero-changed");
    CHECK_EQ_INT(config_update_account(&ctx, &changed), -1); /* pre-fix: 0 */
    CHECK(memcmp(&ctx.accounts[0], &before, sizeof(before)) == 0);
    CHECK_EQ_INT(config_validate(&ctx), -1); /* pre-fix: 0 */

    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    CHECK_EQ_INT(join_path(path, sizeof(path), dir, "/accounts.toml"), 0);
    CHECK_EQ_INT(join_path(hint, sizeof(hint), dir, "/.resume-hint"), 0);
    CHECK_EQ_INT(config_save(&ctx, path), -1); /* pre-fix: emits accounts.0 */
    CHECK(access(path, F_OK) != 0);
    CHECK(access(hint, F_OK) != 0);
}

TEST(current_pointer_rebinds_after_direct_array_compaction) {
    gitswitch_ctx_t ctx;

    seed_three_accounts(&ctx);
    CHECK_EQ_INT(config_remove_account(&ctx, 1), 0);
    CHECK(current_pointer_is_valid(&ctx));
    CHECK(ctx.current_account == &ctx.accounts[0]);
    CHECK_EQ_INT(ctx.current_account ? (int)ctx.current_account->id : -1, 2);

    seed_three_accounts(&ctx);
    CHECK_EQ_INT(config_remove_account(&ctx, 2), 0);
    CHECK(current_pointer_is_valid(&ctx));
    CHECK(ctx.current_account == NULL);

    seed_three_accounts(&ctx);
    CHECK_EQ_INT(config_remove_account(&ctx, 3), 0);
    CHECK(current_pointer_is_valid(&ctx));
    CHECK(ctx.current_account == &ctx.accounts[1]);
    CHECK_EQ_INT(ctx.current_account ? (int)ctx.current_account->id : -1, 2);
}

TEST(failed_reload_preserves_complete_context) {
    static const char missing_scope[] =
        "[settings]\n"
        "[accounts.1]\nname = \"alice\"\nemail = \"a@b.com\"\n";
    static const char unsafe_legacy_active[] =
        "[settings]\ndefault_scope = \"local\"\n"
        "active_account = \"bad/name\"\n"
        "[accounts.1]\nname = \"alice\"\nemail = \"a@b.com\"\n";
    static const char replacement[] =
        "[settings]\ndefault_scope = \"local\"\n"
        "[accounts.1]\nname = \"alice\"\nemail = \"a@b.com\"\n";
    static const char malformed_state[] = "garbage\n";
    static const char mismatched_state[] = "ssh\nactive=alice\n";
    char dir[128], path[256], hint[256];
    gitswitch_ctx_t ctx;
    gitswitch_ctx_t *before;

    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    CHECK_EQ_INT(join_path(path, sizeof(path), dir, "/accounts.toml"), 0);
    CHECK_EQ_INT(join_path(hint, sizeof(hint), dir, "/.resume-hint"), 0);

    seed_reload_sentinel(&ctx);
    before = malloc(sizeof(*before));
    CHECK(before != NULL);
    if (!before) return;
    memcpy(before, &ctx, sizeof(*before));

    /* Each case crosses a later mutation boundary in the pre-fix loader:
     * counter reset, settings mutation, model replacement, then active-state
     * validation. A failed reload is one transaction, so none may become
     * observable to the caller. */
    CHECK_EQ_INT(write_config(path, missing_scope, sizeof(missing_scope) - 1U), 0);
    CHECK_EQ_INT(config_load(&ctx, path), -1);
    CHECK(memcmp(&ctx, before, sizeof(ctx)) == 0);
    memcpy(&ctx, before, sizeof(ctx));

    CHECK_EQ_INT(write_config(path, unsafe_legacy_active,
                              sizeof(unsafe_legacy_active) - 1U), 0);
    CHECK_EQ_INT(config_load(&ctx, path), -1);
    CHECK(memcmp(&ctx, before, sizeof(ctx)) == 0);
    memcpy(&ctx, before, sizeof(ctx));

    CHECK_EQ_INT(write_config(path, replacement, sizeof(replacement) - 1U), 0);
    CHECK_EQ_INT(write_config(hint, malformed_state,
                              sizeof(malformed_state) - 1U), 0);
    CHECK_EQ_INT(config_load(&ctx, path), -1);
    CHECK(memcmp(&ctx, before, sizeof(ctx)) == 0);
    memcpy(&ctx, before, sizeof(ctx));

    CHECK_EQ_INT(write_config(hint, mismatched_state,
                              sizeof(mismatched_state) - 1U), 0);
    CHECK_EQ_INT(config_load(&ctx, path), -1);
    CHECK(memcmp(&ctx, before, sizeof(ctx)) == 0);

    free(before);
}

TEST(reload_reconciles_current_account_from_runtime_or_saved_state) {
    static const char unchanged[] =
        "[settings]\ndefault_scope = \"local\"\n"
        "[accounts.2]\nname = \"current-old\"\nemail = \"current@x.com\"\n"
        "[accounts.3]\nname = \"after\"\nemail = \"after@x.com\"\n"
        "[accounts.1]\nname = \"before\"\nemail = \"before@x.com\"\n";
    static const char renamed[] =
        "[settings]\ndefault_scope = \"local\"\n"
        "[accounts.2]\nname = \"current-new\"\nemail = \"current@x.com\"\n"
        "[accounts.3]\nname = \"after\"\nemail = \"after@x.com\"\n";
    static const char removed_current[] =
        "[settings]\ndefault_scope = \"local\"\n"
        "[accounts.1]\nname = \"before\"\nemail = \"before@x.com\"\n"
        "[accounts.3]\nname = \"after\"\nemail = \"after@x.com\"\n";
    static const char saved_state[] = "none\nactive=current-old\n";
    const char *old_runtime = getenv("XDG_RUNTIME_DIR");
    bool had_runtime = old_runtime != NULL;
    char saved_runtime[MAX_PATH_LEN] = "";
    char dir[128], path[256], hint[256];
    gitswitch_ctx_t ctx;
    int listener;

    if (had_runtime) snprintf(saved_runtime, sizeof(saved_runtime), "%s", old_runtime);

    /* A different live account must override the pointer inherited from the
     * pre-reload model. This is the causal M7 case: before the fix the early
     * ID rebind made accounts_detect_current() return without inspection. */
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", dir, 1), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    seed_three_accounts(&ctx);
    CHECK_EQ_INT(write_config(path, unchanged, sizeof(unchanged) - 1U), 0);
    listener = install_live_current_socket(dir, "after");
    CHECK(listener >= 0);
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK(current_pointer_is_valid(&ctx));
    CHECK_EQ_INT(ctx.current_account ? (int)ctx.current_account->id : -1, 3);
    if (ctx.current_account) CHECK_STR_EQ(ctx.current_account->name, "after");
    if (listener >= 0) close(listener);

    /* An unchanged account is rebound only when validated persisted state says
     * it remains active; the stale pointer itself is not evidence. */
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", dir, 1), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    seed_three_accounts(&ctx);
    CHECK_EQ_INT(write_config(path, unchanged, sizeof(unchanged) - 1U), 0);
    CHECK_EQ_INT(write_config(hint, saved_state, sizeof(saved_state) - 1U), 0);
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK(current_pointer_is_valid(&ctx));
    CHECK(ctx.current_account == &ctx.accounts[0]);
    CHECK_EQ_INT(ctx.current_account ? (int)ctx.current_account->id : -1, 2);

    /* A stable ID whose name changed cannot inherit the old current status
     * when the only live evidence still names the removed identity. */
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", dir, 1), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    seed_three_accounts(&ctx);
    CHECK_EQ_INT(write_config(path, renamed, sizeof(renamed) - 1U), 0);
    listener = install_live_current_socket(dir, "current-old");
    CHECK(listener >= 0);
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK(current_pointer_is_valid(&ctx));
    CHECK(ctx.current_account == NULL);
    if (listener >= 0) close(listener);

    /* Removing the old current account likewise leaves no validated binding. */
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", dir, 1), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    seed_three_accounts(&ctx);
    CHECK_EQ_INT(write_config(path, removed_current,
                              sizeof(removed_current) - 1U), 0);
    listener = install_live_current_socket(dir, "current-old");
    CHECK(listener >= 0);
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK(current_pointer_is_valid(&ctx));
    CHECK(ctx.current_account == NULL);
    if (listener >= 0) close(listener);

    /* With neither live nor saved evidence, even an unchanged account is not
     * reported as current merely because the caller once pointed at it. */
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", dir, 1), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    seed_three_accounts(&ctx);
    CHECK_EQ_INT(write_config(path, unchanged, sizeof(unchanged) - 1U), 0);
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK(current_pointer_is_valid(&ctx));
    CHECK(ctx.current_account == NULL);

    if (had_runtime) setenv("XDG_RUNTIME_DIR", saved_runtime, 1);
    else unsetenv("XDG_RUNTIME_DIR");
}

TEST(load_rejects_symlinked_config) {
    /* The symlink target is a file that passes every *content* check (ours,
     * 0600, valid TOML), so the old stat()-based validation followed the
     * link and accepted it; the fix must refuse on the link itself. */
    char dir[128], real[256], link[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(real, sizeof(real), "%s/victim.toml", dir);
    snprintf(link, sizeof(link), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(real, valid_config, strlen(valid_config)), 0);
    CHECK_EQ_INT(symlink(real, link), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, link), -1);
    CHECK_EQ_INT(ctx.account_count, 0);
}

/* ---- AR-04 L2: the final config-directory component is no-follow -------- */

static void check_symlinked_config_directory_refused(mode_t target_mode) {
    char home[128], saved_home[512];
    char dotconfig[256], target[256], link[256], sentinel[512];
    char accounts[512], linked_accounts[512], lock[512], hint[512];
    char before[128], after[128];
    struct stat link_st, target_st;
    gitswitch_ctx_t ctx;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(home, sizeof(home)), 0);
    snprintf(dotconfig, sizeof(dotconfig), "%s/.config", home);
    snprintf(target, sizeof(target), "%s/config-target", home);
    CHECK_EQ_INT(join_path(link, sizeof(link), dotconfig, "/gitswitch"), 0);
    snprintf(sentinel, sizeof(sentinel), "%s/sentinel", target);
    snprintf(accounts, sizeof(accounts), "%s/accounts.toml", target);
    snprintf(linked_accounts, sizeof(linked_accounts), "%s/accounts.toml", link);
    snprintf(lock, sizeof(lock), "%s/.config.lock", target);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", target);
    CHECK_EQ_INT(mkdir(dotconfig, 0700), 0);
    CHECK_EQ_INT(mkdir(target, target_mode), 0);
    CHECK_EQ_INT(chmod(target, target_mode), 0); /* do not let umask alter the case */
    CHECK_EQ_INT(write_config(sentinel, "target-content\n", 15), 0);
    CHECK(slurp(sentinel, before, sizeof(before)) > 0);
    CHECK_EQ_INT(symlink(target, link), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_init(&ctx), -1);

    /* Every mutating entry point that prepares the directory must refuse too;
     * no config, lock, or resume marker may appear through the link. */
    int lock_fd = config_write_lock();
    CHECK_EQ_INT(lock_fd, -1);
    if (lock_fd >= 0) config_write_unlock(lock_fd);
    CHECK_EQ_INT(config_create_default(linked_accounts), -1);

    CHECK_EQ_INT(lstat(link, &link_st), 0);
    CHECK(S_ISLNK(link_st.st_mode));
    CHECK_EQ_INT(stat(target, &target_st), 0);
    CHECK_EQ_INT((long)(target_st.st_mode & 0777), (long)target_mode);
    CHECK(slurp(sentinel, after, sizeof(after)) > 0);
    CHECK_STR_EQ(after, before);
    CHECK(access(accounts, F_OK) != 0);
    CHECK(access(lock, F_OK) != 0);
    CHECK(access(hint, F_OK) != 0);

    restore_home_env(saved_home);
}

TEST(config_init_rejects_symlinked_final_directory_without_mutation) {
    check_symlinked_config_directory_refused(0755);
    check_symlinked_config_directory_refused(0700);
}

TEST(config_init_rejects_nondirectory_final_components) {
    char home[128], saved_home[512], dotconfig[256], final[256];
    char before[64], after[64];
    struct stat st;
    gitswitch_ctx_t ctx;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(home, sizeof(home)), 0);
    snprintf(dotconfig, sizeof(dotconfig), "%s/.config", home);
    CHECK_EQ_INT(join_path(final, sizeof(final), dotconfig, "/gitswitch"), 0);
    CHECK_EQ_INT(mkdir(dotconfig, 0700), 0);
    CHECK_EQ_INT(write_config(final, "not-a-directory\n", 16), 0);
    CHECK(slurp(final, before, sizeof(before)) > 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_init(&ctx), -1);
    CHECK_EQ_INT(lstat(final, &st), 0);
    CHECK(S_ISREG(st.st_mode));
    CHECK(slurp(final, after, sizeof(after)) > 0);
    CHECK_STR_EQ(after, before);

    CHECK_EQ_INT(unlink(final), 0);
    CHECK_EQ_INT(mkfifo(final, 0600), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_init(&ctx), -1);
    CHECK_EQ_INT(lstat(final, &st), 0);
    CHECK(S_ISFIFO(st.st_mode));

    restore_home_env(saved_home);
}

TEST(config_init_secures_real_or_absent_final_directory) {
    char home[128], saved_home[512], dotconfig[256], final[256];
    char accounts[512];
    struct stat st;
    gitswitch_ctx_t ctx;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(home, sizeof(home)), 0);
    snprintf(dotconfig, sizeof(dotconfig), "%s/.config", home);
    CHECK_EQ_INT(join_path(final, sizeof(final), dotconfig, "/gitswitch"), 0);
    CHECK_EQ_INT(mkdir(dotconfig, 0700), 0);
    CHECK_EQ_INT(mkdir(final, 0755), 0);
    CHECK_EQ_INT(chmod(final, 0755), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_init(&ctx), 0);
    CHECK_EQ_INT(lstat(final, &st), 0);
    CHECK(S_ISDIR(st.st_mode));
    CHECK_EQ_INT((long)(st.st_mode & 0777), 0700);
    snprintf(accounts, sizeof(accounts), "%s/accounts.toml", final);
    CHECK_EQ_INT(access(accounts, F_OK), -1);
    CHECK_EQ_INT(errno, ENOENT);

    /* Absent final component (and parent) is still created normally. */
    char home2[128], final2[256];
    CHECK_EQ_INT(make_scratch_dir(home2, sizeof(home2)), 0);
    CHECK_EQ_INT(setenv("HOME", home2, 1), 0);
    snprintf(final2, sizeof(final2), "%s/.config/gitswitch", home2);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_init(&ctx), 0);
    CHECK_EQ_INT(lstat(final2, &st), 0);
    CHECK(S_ISDIR(st.st_mode));
    CHECK_EQ_INT((long)(st.st_mode & 0777), 0700);
    snprintf(accounts, sizeof(accounts), "%s/accounts.toml", final2);
    CHECK_STR_EQ(ctx.config.config_path, accounts);
    CHECK_EQ_INT(access(accounts, F_OK), -1);
    CHECK_EQ_INT(errno, ENOENT);

    restore_home_env(saved_home);
}

TEST(config_get_path_uses_home_or_passwd_without_filesystem_mutation) {
    char root[128];
    char saved_home[512];
    char home_a[256];
    char home_b[256];
    char path[MAX_PATH_LEN];
    char expected[MAX_PATH_LEN];
    struct passwd *pw;
    struct stat missing;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(root, sizeof(root)), 0);
    snprintf(home_a, sizeof(home_a), "%s/not-created-a", root);
    snprintf(home_b, sizeof(home_b), "%s/not-created-b", root);

    CHECK_EQ_INT(setenv("HOME", home_a, 1), 0);
    CHECK_EQ_INT(config_get_path(path, sizeof(path)), 0);
    CHECK(snprintf(expected, sizeof(expected),
                   "%s/.config/gitswitch/accounts.toml", home_a) <
          (int)sizeof(expected));
    CHECK_STR_EQ(path, expected);
    CHECK_EQ_INT(lstat(home_a, &missing), -1);
    CHECK_EQ_INT(errno, ENOENT);

    CHECK_EQ_INT(setenv("HOME", home_b, 1), 0);
    CHECK_EQ_INT(config_get_path(path, sizeof(path)), 0);
    CHECK(snprintf(expected, sizeof(expected),
                   "%s/.config/gitswitch/accounts.toml", home_b) <
          (int)sizeof(expected));
    CHECK_STR_EQ(path, expected);
    CHECK_EQ_INT(lstat(home_b, &missing), -1);
    CHECK_EQ_INT(errno, ENOENT);

    CHECK_EQ_INT(unsetenv("HOME"), 0);
    pw = getpwuid(getuid());
    CHECK(pw != NULL);
    if (pw) {
        CHECK_EQ_INT(config_get_path(path, sizeof(path)), 0);
        CHECK(snprintf(expected, sizeof(expected),
                       "%s/.config/gitswitch/accounts.toml", pw->pw_dir) <
              (int)sizeof(expected));
        CHECK_STR_EQ(path, expected);
    }

    restore_home_env(saved_home);
    ts_rm_rf(root);
}

/* ---- AR-04: private metadata nodes are no-follow and nonblocking -------- */

TEST(config_lock_rejects_symlink_fifo_and_unsafe_mode) {
    char home[128], saved_home[512], dotconfig[256], config_dir[512];
    char lock[640], victim[640], before[64], after[64];
    struct stat st;
    int fd, fifo_reader;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(home, sizeof(home)), 0);
    snprintf(dotconfig, sizeof(dotconfig), "%s/.config", home);
    snprintf(config_dir, sizeof(config_dir), "%s/gitswitch", dotconfig);
    snprintf(lock, sizeof(lock), "%s/.config.lock", config_dir);
    snprintf(victim, sizeof(victim), "%s/lock-victim", home);
    CHECK_EQ_INT(mkdir(dotconfig, 0700), 0);
    CHECK_EQ_INT(mkdir(config_dir, 0700), 0);
    CHECK_EQ_INT(write_config(victim, "victim-content\n", 15), 0);
    CHECK(slurp(victim, before, sizeof(before)) > 0);
    CHECK_EQ_INT(symlink(victim, lock), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);

    fd = config_write_lock();
    CHECK_EQ_INT(fd, -1); /* pre-fix: locks the symlink target */
    if (fd >= 0) config_write_unlock(fd);
    CHECK_EQ_INT(lstat(lock, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
    CHECK(slurp(victim, after, sizeof(after)) > 0);
    CHECK_STR_EQ(after, before);

    CHECK_EQ_INT(unlink(lock), 0);
    CHECK_EQ_INT(mkfifo(lock, 0600), 0);
    /* Keep a nonblocking reader open so the old O_WRONLY path cannot hang the
     * regression process; it would open and incorrectly return a FIFO fd. */
    fifo_reader = open(lock, O_RDONLY | O_NONBLOCK);
    CHECK(fifo_reader >= 0);
    fd = config_write_lock();
    CHECK_EQ_INT(fd, -1);
    if (fd >= 0) config_write_unlock(fd);
    if (fifo_reader >= 0) close(fifo_reader);

    CHECK_EQ_INT(unlink(lock), 0);
    CHECK_EQ_INT(write_config(lock, "", 0), 0);
    CHECK_EQ_INT(chmod(lock, 0660), 0);
    fd = config_write_lock();
    CHECK_EQ_INT(fd, -1);
    if (fd >= 0) config_write_unlock(fd);

    CHECK_EQ_INT(chmod(lock, 0600), 0);
    fd = config_write_lock();
    CHECK(fd >= 0);
    if (fd >= 0) config_write_unlock(fd);

    restore_home_env(saved_home);
}

static int config_lock_child_contended(void) {
    pid_t pid = fork();
    int status = 0;

    if (pid < 0) return -1;
    if (pid == 0) {
        int token = config_write_lock();
        if (token >= 0) {
            config_write_unlock(token);
            _exit(1); /* entered a replacement lock domain */
        }
        if (errno == EWOULDBLOCK
#if EAGAIN != EWOULDBLOCK
            || errno == EAGAIN
#endif
        ) {
            _exit(0);
        }
        _exit(2);
    }
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

/* AR-08 L7: config_write_lock exposes the shared private-lock token. If a
 * caller closes that opaque handle and the fd number is reused, unlock must
 * preserve the replacement while still retiring every lock reference. */
TEST(config_lock_release_preserves_reused_fd_and_retires_context) {
    char home[128], saved_home[512], dotconfig[256], config_dir[512];
    char lock_path[640];
    int token = -1;
    int replacement = -1;
    bool released = false;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(home, sizeof(home)), 0);
    snprintf(dotconfig, sizeof(dotconfig), "%s/.config", home);
    snprintf(config_dir, sizeof(config_dir), "%s/gitswitch", dotconfig);
    snprintf(lock_path, sizeof(lock_path), "%s/.config.lock", config_dir);
    CHECK_EQ_INT(mkdir(dotconfig, 0700), 0);
    CHECK_EQ_INT(mkdir(config_dir, 0700), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);

    token = config_write_lock();
    CHECK(token >= 0);
    if (token < 0) goto cleanup;
    close(token);
    replacement = open("/dev/null", O_RDONLY | O_CLOEXEC);
    CHECK(replacement >= 0);
    if (replacement < 0) goto cleanup;
    if (replacement != token) {
        CHECK_EQ_INT(dup2(replacement, token), token);
        close(replacement);
        replacement = token;
        CHECK_EQ_INT(fcntl(replacement, F_SETFD, FD_CLOEXEC), 0);
    }

    errno = ENOTTY;
    config_write_unlock(token);
    released = true;
    CHECK_EQ_INT(errno, ENOTTY);
    CHECK(fcntl(replacement, F_GETFD) >= 0);
    /* The existing helper exits 1 when it acquired. An identity-mismatch
     * early return would leave the parent's registry lock held and yield 0. */
    CHECK_EQ_INT(config_lock_child_contended(), 1);

cleanup:
    if (!released && token >= 0) config_write_unlock(token);
    if (replacement >= 0) close(replacement);
    (void)unlink(lock_path);
    (void)rmdir(config_dir);
    (void)rmdir(dotconfig);
    (void)rmdir(home);
    restore_home_env(saved_home);
}

TEST(config_lock_survives_post_acquisition_namespace_replacement) {
    char home[128], saved_home[512], dotconfig[256], config_dir[512];
    char moved_dir[512], lock[640], moved_lock[640];
    int token;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(home, sizeof(home)), 0);
    snprintf(dotconfig, sizeof(dotconfig), "%s/.config", home);
    snprintf(config_dir, sizeof(config_dir), "%s/gitswitch", dotconfig);
    snprintf(moved_dir, sizeof(moved_dir), "%s/gitswitch.moved", dotconfig);
    snprintf(lock, sizeof(lock), "%s/.config.lock", config_dir);
    snprintf(moved_lock, sizeof(moved_lock), "%s/.config.lock.old", config_dir);
    CHECK_EQ_INT(mkdir(dotconfig, 0700), 0);
    CHECK_EQ_INT(mkdir(config_dir, 0700), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);

    token = config_write_lock();
    CHECK(token >= 0);
    CHECK_EQ_INT(rename(lock, moved_lock), 0);
    CHECK_EQ_INT(write_config(lock, "", 0), 0);
    CHECK_EQ_INT(config_lock_child_contended(), 0);
    if (token >= 0) config_write_unlock(token);

    token = config_write_lock();
    CHECK(token >= 0);
    CHECK_EQ_INT(rename(config_dir, moved_dir), 0);
    CHECK_EQ_INT(mkdir(config_dir, 0700), 0);
    CHECK_EQ_INT(config_lock_child_contended(), 0);
    if (token >= 0) config_write_unlock(token);

    token = config_write_lock();
    CHECK(token >= 0);
    if (token >= 0) config_write_unlock(token);
    restore_home_env(saved_home);
}

TEST(config_init_preserves_symlinked_parent_policy) {
    char home[128], saved_home[512], parent[256], parent_link[256];
    char final[512], accounts[512];
    struct stat st;
    gitswitch_ctx_t ctx;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(home, sizeof(home)), 0);
    snprintf(parent, sizeof(parent), "%s/config-parent", home);
    snprintf(parent_link, sizeof(parent_link), "%s/.config", home);
    snprintf(final, sizeof(final), "%s/gitswitch", parent);
    CHECK_EQ_INT(join_path(accounts, sizeof(accounts), final,
                           "/accounts.toml"), 0);
    CHECK_EQ_INT(mkdir(parent, 0700), 0);
    CHECK_EQ_INT(mkdir(final, 0755), 0);
    CHECK_EQ_INT(chmod(final, 0755), 0);
    CHECK_EQ_INT(write_config(accounts, valid_config, strlen(valid_config)), 0);
    CHECK_EQ_INT(symlink(parent, parent_link), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_init(&ctx), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    CHECK_EQ_INT(lstat(parent_link, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
    CHECK_EQ_INT(lstat(final, &st), 0);
    CHECK(S_ISDIR(st.st_mode));
    CHECK_EQ_INT((long)(st.st_mode & 0777), 0700);

    restore_home_env(saved_home);
}

/* ---- cfg-symlink-01: write + backup path ---- */

TEST(save_refuses_symlinked_config_path) {
    char dir[128], victim[256], link[256], buf[1024];
    const char *secret = "SECRET-VICTIM-CONTENT\n";
    gitswitch_ctx_t ctx;
    struct stat st;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(victim, sizeof(victim), "%s/victim.toml", dir);
    snprintf(link, sizeof(link), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(victim, secret, strlen(secret)), 0);
    CHECK_EQ_INT(symlink(victim, link), 0);

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&ctx.accounts[0], 1, "alice", "a@b.com", "day job");
    ctx.account_count = 1;

    /* Must fail closed: no write through the link, no backup made of the
     * link target, victim bytes untouched, and the link still a link. */
    CHECK_EQ_INT(config_save(&ctx, link), -1);
    slurp(victim, buf, sizeof(buf));
    CHECK_STR_EQ(buf, secret);
    CHECK_EQ_INT(lstat(link, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
}

TEST(backup_refuses_symlinked_source) {
    /* config_backup on a symlinked config would read *through* the link,
     * copying another user's file into a 0600 backup we own. */
    char dir[128], victim[256], link[256];
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(victim, sizeof(victim), "%s/victim.toml", dir);
    snprintf(link, sizeof(link), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(victim, "x\n", 2), 0);
    CHECK_EQ_INT(symlink(victim, link), 0);

    CHECK_EQ_INT(config_backup(link), -1);
}

TEST(save_and_reload_regular_path_roundtrip) {
    /* Normal operation must be unchanged: save to a real path, verify the
     * installed file is 0600, reload it and find the account again. Save a
     * second time to exercise the (no-follow) backup branch too. */
    char dir[128], path[256];
    static const char v5_fingerprint[] =
        "0123456789ABCDEF0123456789ABCDEF"
        "0123456789ABCDEF0123456789ABCDEF";
    char prefixed_v5[MAX_GPG_SELECTOR_LEN];
    char overlong[MAX_GPG_SELECTOR_LEN];
    gitswitch_ctx_t ctx, reloaded;
    struct stat st;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&ctx.accounts[0], 1, "alice", "a@b.com", "day job");
    CHECK_EQ_INT((int)strlen(v5_fingerprint), 64);
    CHECK(snprintf(ctx.accounts[0].gpg_key_id,
                   sizeof(ctx.accounts[0].gpg_key_id), "%s",
                   v5_fingerprint) <
          (int)sizeof(ctx.accounts[0].gpg_key_id));
    ctx.accounts[0].gpg_enabled = true;
    ctx.accounts[0].gpg_signing_enabled = true;
    fill_account(&ctx.accounts[1], 2, "bob", "b@b.com", "prefixed");
    CHECK_EQ_INT(snprintf(prefixed_v5, sizeof(prefixed_v5), "0x%s",
                          v5_fingerprint), 66);
    CHECK_EQ_INT(snprintf(ctx.accounts[1].gpg_key_id,
                          sizeof(ctx.accounts[1].gpg_key_id), "%s",
                          prefixed_v5), 66);
    ctx.accounts[1].gpg_enabled = true;
    ctx.accounts[1].gpg_signing_enabled = false;
    ctx.account_count = 2;

    CHECK_EQ_INT(config_save(&ctx, path), 0);
    CHECK_EQ_INT(lstat(path, &st), 0);
    CHECK(S_ISREG(st.st_mode));
    CHECK_EQ_INT(st.st_mode & 0777, 0600);

    CHECK_EQ_INT(config_save(&ctx, path), 0); /* second save: backup branch */

    memset(&reloaded, 0, sizeof(reloaded));
    CHECK_EQ_INT(config_load(&reloaded, path), 0);
    CHECK_EQ_INT(reloaded.account_count, 2);
    if (reloaded.account_count == 2) {
        CHECK_STR_EQ(reloaded.accounts[0].name, "alice");
        CHECK_STR_EQ(reloaded.accounts[0].gpg_key_id, v5_fingerprint);
        CHECK(reloaded.accounts[0].gpg_enabled);
        CHECK(reloaded.accounts[0].gpg_signing_enabled);
        CHECK_STR_EQ(reloaded.accounts[1].name, "bob");
        CHECK_STR_EQ(reloaded.accounts[1].gpg_key_id, prefixed_v5);
        CHECK(reloaded.accounts[1].gpg_enabled);
        CHECK(!reloaded.accounts[1].gpg_signing_enabled);
    }

    /* Persistence must refuse 65 fingerprint digits even though the selector
     * field has room for a valid 0x-prefixed 64-digit value. */
    memset(overlong, 'A', 65);
    overlong[65] = '\0';
    CHECK_EQ_INT(snprintf(ctx.accounts[1].gpg_key_id,
                          sizeof(ctx.accounts[1].gpg_key_id), "%s",
                          overlong), 65);
    CHECK_EQ_INT(config_save(&ctx, path), -1);
}

TEST(account_model_invariant_blocks_lossy_states_before_mutation) {
    char dir[128], path[256], key[256];
    char before[4096], after[4096];
    gitswitch_ctx_t baseline;

    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(key, sizeof(key), "%s/id_model", dir);
    CHECK_EQ_INT(write_config(
                     key,
                     "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n",
                     sizeof("-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n") -
                         1U),
                 0);

    memset(&baseline, 0, sizeof(baseline));
    baseline.config.default_scope = GIT_SCOPE_LOCAL;
    fill_account(&baseline.accounts[0], 1, "baseline",
                 "baseline@example.com", "baseline");
    baseline.account_count = 1;
    CHECK_EQ_INT(config_save(&baseline, path), 0);
    CHECK(slurp(path, before, sizeof(before)) > 0);

    for (int invalid = INVALID_SSH_ENABLED_WITHOUT_KEY;
         invalid <= INVALID_GPG_DISABLED_WITH_SIGNING; invalid++) {
        gitswitch_ctx_t api;
        gitswitch_ctx_t direct;
        account_t account;

        fill_invalid_account_model(&account,
                                   (invalid_account_model_t)invalid, key);
        memset(&api, 0, sizeof(api));
        CHECK_EQ_INT(config_add_account(&api, &account), -1);
        CHECK_EQ_INT(api.account_count, 0);
        CHECK_EQ_INT(accounts_validate(&account), -1);

        memset(&direct, 0, sizeof(direct));
        direct.config.default_scope = GIT_SCOPE_LOCAL;
        direct.accounts[0] = account;
        direct.account_count = 1;
        CHECK_EQ_INT(config_validate(&direct), -1);
        CHECK_EQ_INT(config_save(&direct, path), -1);
        CHECK(slurp(path, after, sizeof(after)) > 0);
        CHECK_STR_EQ(after, before);
    }

    {
        gitswitch_ctx_t api;
        account_t account;

        memset(&api, 0, sizeof(api));
        fill_account(&account, 1, "legacy-api", "legacy@example.com",
                     "legacy api");
        account.ssh_enabled = true;
        strncpy(account.ssh_key_path, key,
                sizeof(account.ssh_key_path) - 1U);
        strncpy(account.ssh_host_alias, "git.example.test",
                sizeof(account.ssh_host_alias) - 1U);
        CHECK_EQ_INT(config_add_account(&api, &account), 0);
        CHECK_EQ_INT(api.account_count, 1);
        if (api.account_count == 1) {
            CHECK_STR_EQ(api.accounts[0].ssh_hostname, "git.example.test");

            /* Admission normalizes the legacy literal form. A hand-built
             * context that bypasses admission must not be changed while it is
             * being saved. */
            api.accounts[0].ssh_hostname[0] = '\0';
            CHECK_EQ_INT(config_validate(&api), -1);
            CHECK_EQ_INT(config_save(&api, path), -1);
            CHECK(slurp(path, after, sizeof(after)) > 0);
            CHECK_STR_EQ(after, before);
        }
    }

    {
        gitswitch_ctx_t api;
        account_t account;

        memset(&api, 0, sizeof(api));
        fill_account(&account, 1, "wildcard", "wildcard@example.com",
                     "wildcard");
        account.ssh_enabled = true;
        strncpy(account.ssh_key_path, key,
                sizeof(account.ssh_key_path) - 1U);
        strncpy(account.ssh_host_alias, "github-*",
                sizeof(account.ssh_host_alias) - 1U);
        CHECK_EQ_INT(config_add_account(&api, &account), -1);
        CHECK_EQ_INT(api.account_count, 0);
    }
}

TEST(account_model_admitted_states_roundtrip_exactly) {
    typedef struct {
        bool ssh_enabled;
        const char *ssh_alias;
        const char *ssh_hostname;
        bool gpg_enabled;
        bool gpg_signing_enabled;
    } model_case_t;
    static const model_case_t cases[] = {
        {false, NULL, NULL, false, false},
        {true, NULL, NULL, false, false},
        {true, NULL, "github.com", false, false},
        {true, "github-work", "github.com", false, false},
        {false, NULL, NULL, true, false},
        {false, NULL, NULL, true, true},
        {true, "github-work", "github.com", true, true},
    };
    char dir[128], path[256], key[256];

    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(key, sizeof(key), "%s/id_roundtrip", dir);
    CHECK_EQ_INT(write_config(
                     key,
                     "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n",
                     sizeof("-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n") -
                         1U),
                 0);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        gitswitch_ctx_t ctx;
        gitswitch_ctx_t reloaded;
        account_t account;

        CHECK(snprintf(path, sizeof(path), "%s/accounts-%zu.toml", dir, i) <
              (int)sizeof(path));
        memset(&ctx, 0, sizeof(ctx));
        ctx.config.default_scope = GIT_SCOPE_LOCAL;
        fill_account(&account, 1, "roundtrip", "roundtrip@example.com",
                     "roundtrip");
        if (cases[i].ssh_enabled) {
            account.ssh_enabled = true;
            strncpy(account.ssh_key_path, key,
                    sizeof(account.ssh_key_path) - 1U);
        }
        if (cases[i].ssh_alias) {
            strncpy(account.ssh_host_alias, cases[i].ssh_alias,
                    sizeof(account.ssh_host_alias) - 1U);
        }
        if (cases[i].ssh_hostname) {
            strncpy(account.ssh_hostname, cases[i].ssh_hostname,
                    sizeof(account.ssh_hostname) - 1U);
        }
        if (cases[i].gpg_enabled) {
            account.gpg_enabled = true;
            strncpy(account.gpg_key_id, "ABCDEF0123456789",
                    sizeof(account.gpg_key_id) - 1U);
        }
        account.gpg_signing_enabled = cases[i].gpg_signing_enabled;

        CHECK_EQ_INT(config_add_account(&ctx, &account), 0);
        CHECK_EQ_INT(ctx.account_count, 1);
        CHECK_EQ_INT(config_save(&ctx, path), 0);

        memset(&reloaded, 0, sizeof(reloaded));
        CHECK_EQ_INT(config_load(&reloaded, path), 0);
        CHECK_EQ_INT(reloaded.account_count, 1);
        if (ctx.account_count == 1 && reloaded.account_count == 1) {
            CHECK_EQ_INT(reloaded.accounts[0].ssh_enabled,
                         ctx.accounts[0].ssh_enabled);
            CHECK_STR_EQ(reloaded.accounts[0].ssh_key_path,
                         ctx.accounts[0].ssh_key_path);
            CHECK_STR_EQ(reloaded.accounts[0].ssh_host_alias,
                         ctx.accounts[0].ssh_host_alias);
            CHECK_STR_EQ(reloaded.accounts[0].ssh_hostname,
                         ctx.accounts[0].ssh_hostname);
            CHECK_EQ_INT(reloaded.accounts[0].gpg_enabled,
                         ctx.accounts[0].gpg_enabled);
            CHECK_EQ_INT(reloaded.accounts[0].gpg_signing_enabled,
                         ctx.accounts[0].gpg_signing_enabled);
            CHECK_STR_EQ(reloaded.accounts[0].gpg_key_id,
                         ctx.accounts[0].gpg_key_id);
        }
    }
}

/* ---- AR-07 M13 prerequisite: alias and canonical host are distinct ------ */

TEST(ssh_hostname_load_save_and_shared_destination_roundtrip) {
    char home[128], saved_home[512], dotconfig[256], config_dir[512];
    char path[640], key[256], cfg[4096], after[4096];
    gitswitch_ctx_t ctx, reloaded;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(home, sizeof(home)), 0);
    snprintf(dotconfig, sizeof(dotconfig), "%s/.config", home);
    snprintf(config_dir, sizeof(config_dir), "%s/gitswitch", dotconfig);
    snprintf(path, sizeof(path), "%s/accounts.toml", config_dir);
    snprintf(key, sizeof(key), "%s/id_test", home);
    CHECK_EQ_INT(mkdir(dotconfig, 0700), 0);
    CHECK_EQ_INT(mkdir(config_dir, 0700), 0);
    CHECK_EQ_INT(write_config(key,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n",
        sizeof("-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n") - 1), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);

    CHECK(snprintf(cfg, sizeof(cfg),
                   "[settings]\n"
                   "default_scope = \"local\"\n"
                   "[accounts.1]\n"
                   "name = \"work\"\n"
                   "email = \"work@example.com\"\n"
                   "ssh_key = \"%s\"\n"
                   "ssh_host = \"github-work\"\n"
                   "ssh_hostname = \"github.com\"\n"
                   "[accounts.2]\n"
                   "name = \"personal\"\n"
                   "email = \"me@example.com\"\n"
                   "ssh_key = \"%s\"\n"
                   "ssh_host = \"github-personal\"\n"
                   "ssh_hostname = \"github.com\"\n",
                   key, key) < (int)sizeof(cfg));
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 2);
    CHECK_EQ_INT(ctx.unknown_keys_on_load, 0);
    if (ctx.account_count == 2) {
        CHECK_STR_EQ(ctx.accounts[0].ssh_host_alias, "github-work");
        CHECK_STR_EQ(ctx.accounts[0].ssh_hostname, "github.com");
        CHECK_STR_EQ(ctx.accounts[1].ssh_host_alias, "github-personal");
        CHECK_STR_EQ(ctx.accounts[1].ssh_hostname, "github.com");
    }

    /* Canonical hostnames are destinations, not owned namespaces: sharing
     * github.com is valid even though the managed aliases remain distinct. */
    CHECK_EQ_INT(config_save(&ctx, path), 0);
    CHECK(slurp(path, after, sizeof(after)) > 0);
    CHECK_EQ_INT(count_occurrences(after,
                                   "ssh_hostname = \"github.com\""), 2);

    memset(&reloaded, 0, sizeof(reloaded));
    CHECK_EQ_INT(config_load(&reloaded, path), 0);
    CHECK_EQ_INT(reloaded.account_count, 2);
    if (reloaded.account_count == 2) {
        CHECK_STR_EQ(reloaded.accounts[0].ssh_hostname, "github.com");
        CHECK_STR_EQ(reloaded.accounts[1].ssh_hostname, "github.com");
    }
    restore_home_env(saved_home);
}

TEST(legacy_literal_ssh_host_falls_back_and_is_canonicalized) {
    char home[128], saved_home[512], dotconfig[256], config_dir[512];
    char path[640], key[256], cfg[2048], after[4096];
    gitswitch_ctx_t ctx;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(home, sizeof(home)), 0);
    snprintf(dotconfig, sizeof(dotconfig), "%s/.config", home);
    snprintf(config_dir, sizeof(config_dir), "%s/gitswitch", dotconfig);
    snprintf(path, sizeof(path), "%s/accounts.toml", config_dir);
    snprintf(key, sizeof(key), "%s/id_test", home);
    CHECK_EQ_INT(mkdir(dotconfig, 0700), 0);
    CHECK_EQ_INT(mkdir(config_dir, 0700), 0);
    CHECK_EQ_INT(write_config(key,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n",
        sizeof("-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n") - 1), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    CHECK(snprintf(cfg, sizeof(cfg),
                   "[settings]\n"
                   "default_scope = \"local\"\n"
                   "[accounts.1]\n"
                   "name = \"legacy\"\n"
                   "email = \"legacy@example.com\"\n"
                   "ssh_key = \"%s\"\n"
                   "ssh_host = \"git.example.test\"\n",
                   key) < (int)sizeof(cfg));
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    if (ctx.account_count == 1) {
        CHECK_STR_EQ(ctx.accounts[0].ssh_host_alias, "git.example.test");
        CHECK_STR_EQ(ctx.accounts[0].ssh_hostname, "git.example.test");
    }
    CHECK_EQ_INT(config_save(&ctx, path), 0);
    CHECK(slurp(path, after, sizeof(after)) > 0);
    CHECK_EQ_INT(count_occurrences(
                     after, "ssh_hostname = \"git.example.test\""), 1);
    restore_home_env(saved_home);
}

TEST(legacy_wildcard_alias_requires_explicit_canonical_hostname) {
    char dir[128], path[256], key[256], cfg[2048];
    gitswitch_ctx_t ctx;

    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(key, sizeof(key), "%s/id_test", dir);
    CHECK_EQ_INT(write_config(key,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n",
        sizeof("-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n") - 1), 0);
    CHECK(snprintf(cfg, sizeof(cfg),
                   "[settings]\n"
                   "default_scope = \"local\"\n"
                   "[accounts.1]\n"
                   "name = \"legacy-pattern\"\n"
                   "email = \"legacy@example.com\"\n"
                   "ssh_key = \"%s\"\n"
                   "ssh_host = \"github-*\"\n",
                   key) < (int)sizeof(cfg));
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 0);
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 1);
    CHECK_EQ_INT(config_check_rewritable(&ctx), -1);

    /* The pattern itself remains legal when an unambiguous destination is
     * supplied; only using a wildcard as the HostName fallback is rejected. */
    CHECK(snprintf(cfg, sizeof(cfg),
                   "[settings]\n"
                   "default_scope = \"local\"\n"
                   "[accounts.1]\n"
                   "name = \"explicit-pattern\"\n"
                   "email = \"explicit@example.com\"\n"
                   "ssh_key = \"%s\"\n"
                   "ssh_host = \"github-*\"\n"
                   "ssh_hostname = \"github.com\"\n",
                   key) < (int)sizeof(cfg));
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    if (ctx.account_count == 1) {
        CHECK_STR_EQ(ctx.accounts[0].ssh_hostname, "github.com");
    }
}

TEST(ssh_hostname_schema_and_api_reject_unsafe_values) {
    static const char *const invalid[] = {
        "bad host", "bad\thost", "bad\"host", "bad\\host", "bad%h",
        "*.example.com", "host?", "h\xC3\xB6st.example", NULL
    };
    char dir[128], path[256], key[256];
    gitswitch_ctx_t ctx;
    account_t account;

    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(key, sizeof(key), "%s/id_hostname", dir);
    CHECK_EQ_INT(write_config(
                     key,
                     "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n",
                     sizeof("-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n") -
                         1U),
                 0);
    CHECK(strstr(default_config_template,
                 "#ssh_host = \"github.com-work\"") != NULL);
    CHECK(strstr(default_config_template,
                 "#ssh_hostname = \"github.com\"") != NULL);
    CHECK(toml_validate_ssh_hostname("git.example.test:2222"));
    CHECK(toml_validate_ssh_hostname("2001:db8::1"));
    CHECK(!toml_validate_ssh_hostname(""));
    CHECK(toml_validate_ssh_host_alias("github-*"));
    for (size_t i = 0; invalid[i]; i++) {
        CHECK(!toml_validate_ssh_hostname(invalid[i]));
        memset(&ctx, 0, sizeof(ctx));
        fill_account(&account, 1, "bad-host", "bad@example.com", "d");
        account.ssh_enabled = true;
        strncpy(account.ssh_key_path, key,
                sizeof(account.ssh_key_path) - 1U);
        strncpy(account.ssh_hostname, invalid[i],
                sizeof(account.ssh_hostname) - 1);
        CHECK_EQ_INT(config_add_account(&ctx, &account), -1);
        CHECK_EQ_INT(ctx.account_count, 0);
    }

    /* Canonical destinations are deliberately not unique account resources. */
    memset(&ctx, 0, sizeof(ctx));
    fill_account(&account, 1, "one", "one@example.com", "d");
    account.ssh_enabled = true;
    strncpy(account.ssh_key_path, key,
            sizeof(account.ssh_key_path) - 1U);
    strncpy(account.ssh_hostname, "github.com",
            sizeof(account.ssh_hostname) - 1);
    CHECK_EQ_INT(config_add_account(&ctx, &account), 0);
    fill_account(&account, 2, "two", "two@example.com", "d");
    account.ssh_enabled = true;
    strncpy(account.ssh_key_path, key,
            sizeof(account.ssh_key_path) - 1U);
    strncpy(account.ssh_hostname, "github.com",
            sizeof(account.ssh_hostname) - 1);
    CHECK_EQ_INT(config_add_account(&ctx, &account), 0);
    CHECK_EQ_INT(ctx.account_count, 2);

    /* The parser's modeled schema must reject the wrong TOML type rather
     * than let retrieval treat a present key as absent. */
    {
        const char *wrong_type =
            "[settings]\n"
            "default_scope = \"local\"\n"
            "[accounts.1]\n"
            "name = \"typed\"\n"
            "email = \"typed@example.com\"\n"
            "ssh_hostname = true\n";
        CHECK_EQ_INT(write_config(path, wrong_type, strlen(wrong_type)), 0);
        memset(&ctx, 0, sizeof(ctx));
        CHECK_EQ_INT(config_load(&ctx, path), -1);
    }
}

/* ---- int-id-02: identifier lookup must not wrap ---- */

TEST(find_account_rejects_out_of_range_and_noncanonical_ids) {
    gitswitch_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    fill_account(&ctx.accounts[0], 1, "work", "w@x.com", "day job");
    fill_account(&ctx.accounts[1], 2, "home", "h@x.com", "home");
    ctx.account_count = 2;

    /* 2^32 truncated to uint32_t is 0; 2^32+1 is 1; the unsigned conversion
     * of -4294967295 is also 1. None of these may resolve to an account. */
    CHECK(config_find_account(&ctx, "4294967296") == NULL);
    CHECK(config_find_account(&ctx, "4294967297") == NULL);
    CHECK(config_find_account(&ctx, "-4294967295") == NULL);
    /* Ids are stored canonically, so "01" is not id 1 (and no such name). */
    CHECK(config_find_account(&ctx, "01") == NULL);
    /* Way past ULONG_MAX: strtoul clamps + sets ERANGE; must not match. */
    CHECK(config_find_account(&ctx, "99999999999999999999999999") == NULL);

    /* The canonical spelling still resolves. */
    account_t *a = config_find_account(&ctx, "1");
    CHECK(a != NULL);
    if (a) CHECK_EQ_INT(a->id, 1);
}

/* ---- int-id-01/02: load path rejects non-canonical / out-of-range ids ---- */

TEST(load_skips_leading_zero_id_section) {
    /* "accounts.01" used to load as id 1 — an alias of "accounts.1" that
     * dodges the duplicate-id check by spelling. It must be skipped (and
     * counted, so a later save cannot silently erase it). */
    const char *cfg =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.01]\n"
        "name = \"alias\"\n"
        "email = \"a@b.com\"\n";
    char dir[128], path[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 0);
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 1);
}

TEST(load_counts_unknown_keys_in_recognized_sections) {
    /* AR-06 F02: a key gitswitch does not model, sitting inside an otherwise
     * recognized [settings]/[accounts.N] section, is invisible to config_save's
     * rebuild and would be silently erased by the next save. It must be counted
     * so config_check_rewritable refuses the rewrite. */
    const char *cfg =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "custom_flag = \"keepme\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "my_note = \"important\"\n";
    char dir[128], path[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    /* The account still loads; the unknown keys are counted, not dropped. */
    CHECK_EQ_INT(ctx.account_count, 1);
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 0);
    CHECK_EQ_INT(ctx.unknown_sections_on_load, 0);
    CHECK_EQ_INT(ctx.unknown_keys_on_load, 2);
    /* A full rewrite is refused so the keys aren't erased. */
    CHECK_EQ_INT(config_check_rewritable(&ctx), -1);
}

TEST(load_accepts_only_modeled_keys) {
    /* Control: a config with ONLY modeled keys must NOT be flagged. */
    const char *cfg =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "active_account = \"alice\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "description = \"d\"\n";
    char dir[128], path[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.unknown_keys_on_load, 0);
    CHECK_EQ_INT(config_check_rewritable(&ctx), 0);
}

TEST(load_skips_out_of_range_id_section) {
    const char *cfg =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.4294967296]\n"   /* 2^32: would truncate to id 0 */
        "name = \"wrap\"\n"
        "email = \"a@b.com\"\n"
        "\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n";
    char dir[128], path[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    if (ctx.account_count == 1) CHECK_EQ_INT(ctx.accounts[0].id, 1);
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 1);
}

/* AR-02 #5: an over-long name is schema-valid (TOML allows values up to 511
 * bytes; MAX_NAME_LEN is 256), so the whole-file parse succeeds and only the
 * per-field toml_get_string copy fails. That failure used to `continue`
 * WITHOUT counting the section as skipped, so config_save's refuse-to-rewrite
 * guard read zero and the next save (e.g. `remove <other>`) permanently
 * erased the over-long account's section. */
TEST(load_counts_overlong_name_as_skipped_and_save_preserves_it) {
    char cfg[1024];
    char longname[300];
    char dir[128], path[256];
    char after[1024];
    gitswitch_ctx_t ctx;
    FILE *f;
    size_t n;

    memset(longname, 'N', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';
    snprintf(cfg, sizeof(cfg),
             "[settings]\n"
             "default_scope = \"local\"\n"
             "[accounts.1]\n"
             "name = \"%s\"\n"
             "email = \"long@b.com\"\n"
             "\n"
             "[accounts.2]\n"
             "name = \"alice\"\n"
             "email = \"a@b.com\"\n",
             longname);
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 1);          /* alice still loads */
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 1); /* pre-fix: 0 */

    /* The save must refuse the rewrite AND say so in its return value
     * (AR-03 M9: the old `return 0` refusal made add/edit report success
     * for a discarded change), keeping the over-long section on disk for
     * the user to repair. */
    CHECK_EQ_INT(config_save(&ctx, path), -1);
    f = fopen(path, "r");
    CHECK(f != NULL);
    n = f ? fread(after, 1, sizeof(after) - 1, f) : 0;
    if (f) fclose(f);
    after[n] = '\0';
    CHECK(strstr(after, longname) != NULL);      /* pre-fix: erased */
}

/* ---- AR-02 #27: config_save's own scratch registration ---- */

TEST(config_save_registers_and_unregisters_its_temp) {
    /* config_save registers "<path>.tmp.<pid>" for signal cleanup for exactly
     * the span the temp exists (the registration accounts_switch used to make
     * never covered the real save — it ran after the registry was torn down).
     * After a completed save the slot must be RELEASED: a stale registration
     * would let a later emergency cleanup unlink an unrelated file that
     * happens to be recreated at that name. */
    char dir[128], path[256], tmp[512];
    gitswitch_ctx_t ctx;
    FILE *f;

    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&ctx.accounts[0], 1, "alice", "a@b.com", "day job");
    ctx.account_count = 1;
    CHECK_EQ_INT(config_save(&ctx, path), 0);

    /* Recreate a file at the temp's deterministic name and run the scratch
     * cleanup: an unreleased registration would delete it. */
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    f = fopen(tmp, "w");
    CHECK(f != NULL);
    if (f) fclose(f);
    signals_scratch_cleanup();
    CHECK(access(tmp, F_OK) == 0); /* untouched: registration was released */
    unlink(tmp);
}

/* ---- tty-escape: control bytes must not survive to display fields ---- */

TEST(load_strips_cr_from_description) {
    /* The classic line-overwrite spoof: an escape-decoded \r renders
     * "[CURRENT] trusted" over the real row. Locks the layered guarantee —
     * whichever layer handles it, no CR may reach the loaded description.
     * Since AR-03 M6 toml_get_string REFUSES a value sanitization would
     * alter instead of repairing it; the loader now treats such a PRESENT-
     * but-unloadable description as a skip of the whole account (counted,
     * so config_save refuses to rewrite) — the old description-absent
     * fallback (name) was a silent alteration the next save persisted over
     * the user's on-disk bytes (AR-03 T4-owner flag (b)). */
    const char *cfg =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "description = \"evil\\r[CURRENT] trusted\"\n";
    char dir[128], path[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 0);            /* skipped, not repaired */
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 1); /* save guard covers it */
}

TEST(load_rejects_raw_c1_byte_in_file) {
    /* Raw C1 bytes (0x9B is a one-byte CSI) in the file are refused at the
     * character-set gate before parsing; lock that layered guarantee. */
    char cfg[256];
    char dir[128], path[256];
    gitswitch_ctx_t ctx;
    int len = snprintf(cfg, sizeof(cfg),
                       "[accounts.1]\n"
                       "name = \"alice\"\n"
                       "email = \"a@b.com\"\n"
                       "description = \"x%c31mY\"\n", 0x9B);
    CHECK(len > 0);
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, (size_t)len), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), -1);
}

TEST(add_rejects_c1_and_malformed_utf8_in_name) {
    /* The interactive add/edit path takes raw prompt input; validate_name
     * only rejects C0/DEL, so C1 controls used to pass. The name keys the
     * SSH/GPG isolation paths, so it is rejected, not rewritten. */
    gitswitch_ctx_t ctx;
    account_t a;
    memset(&ctx, 0, sizeof(ctx));

    fill_account(&a, 1, "work\xC2\x9B" "31m", "w@x.com", "d"); /* UTF-8 C1 CSI */
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);

    fill_account(&a, 1, "work\x9B" "31m", "w@x.com", "d");     /* bare C1 byte */
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);

    /* AR-02 #28: the OVERLONG spellings of the same C1 CSI (U+009B) — the
     * exact smuggling vector utf8_decode's strictness exists to stop, and
     * previously exercised by no test. 3-byte: E0 82 9B; 4-byte: F0 80 82 9B.
     * A lenient decoder normalizes either back to 0x9B and the terminal
     * executes it; the strict decoder must call both malformed. */
    fill_account(&a, 1, "work\xE0\x82\x9B" "31m", "w@x.com", "d");
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);

    fill_account(&a, 1, "work\xF0\x80\x82\x9B" "31m", "w@x.com", "d");
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);

    fill_account(&a, 1, "caf\xC3\xA9", "w@x.com", "d");        /* plain UTF-8 "café" */
    CHECK_EQ_INT(config_add_account(&ctx, &a), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    if (ctx.account_count == 1) CHECK_STR_EQ(ctx.accounts[0].name, "caf\xC3\xA9");
}

TEST(add_rejects_escape_in_description) {
    gitswitch_ctx_t ctx;
    account_t a;
    memset(&ctx, 0, sizeof(ctx));

    fill_account(&a, 1, "work", "w@x.com", "ok\x1B[31mred");   /* raw ESC */
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);

    /* Overlong-encoded C1 controls in the description (AR-02 #28): the add
     * path fails closed on them just like the raw/2-byte forms. */
    fill_account(&a, 1, "work", "w@x.com", "ok\xE0\x82\x9B" "31m");
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);
    fill_account(&a, 1, "work", "w@x.com", "ok\xF0\x80\x82\x9B" "31m");
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);

    fill_account(&a, 1, "work", "w@x.com", "caf\xC3\xA9 \xE2\x98\x95"); /* "café ☕" */
    CHECK_EQ_INT(config_add_account(&ctx, &a), 0);
    if (ctx.account_count == 1) {
        CHECK_STR_EQ(ctx.accounts[0].description, "caf\xC3\xA9 \xE2\x98\x95");
    }
}

/* ---- hostile account rejected by validate_account_security -------------- */

TEST(config_validate_rejects_hostile_account) {
    char dir[128], key[256], missing[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(key, sizeof(key), "%s/id_ed25519", dir);
    snprintf(missing, sizeof(missing), "%s/no_such_key", dir);
    CHECK_EQ_INT(write_config(key,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n",
        sizeof("-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n") - 1), 0);

    /* Baseline: a well-formed account with a 0600 key validates. */
    memset(&ctx, 0, sizeof(ctx));
    fill_account(&ctx.accounts[0], 1, "work", "w@x.com", "day job");
    ctx.accounts[0].ssh_enabled = true;
    strncpy(ctx.accounts[0].ssh_key_path, key, sizeof(ctx.accounts[0].ssh_key_path) - 1);
    ctx.account_count = 1;
    CHECK_EQ_INT(config_validate(&ctx), 0);

    /* Group/other-readable private key: refused (an attacker who can read
     * the key doesn't need the agent isolation we set up around it). */
    CHECK_EQ_INT(chmod(key, 0644), 0);
    CHECK_EQ_INT(config_validate(&ctx), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_ACCOUNT_INVALID);
    CHECK_EQ_INT(chmod(key, 0600), 0);

    /* Nonexistent key path: refused, not deferred to a runtime ssh failure. */
    strncpy(ctx.accounts[0].ssh_key_path, missing, sizeof(ctx.accounts[0].ssh_key_path) - 1);
    CHECK_EQ_INT(config_validate(&ctx), -1);
    strncpy(ctx.accounts[0].ssh_key_path, key, sizeof(ctx.accounts[0].ssh_key_path) - 1);

    /* Traversal name: it becomes the GNUPGHOME/agent-socket path component. */
    strncpy(ctx.accounts[0].name, "../evil", sizeof(ctx.accounts[0].name) - 1);
    CHECK_EQ_INT(config_validate(&ctx), -1);
    strncpy(ctx.accounts[0].name, "work", sizeof(ctx.accounts[0].name) - 1);

    /* Non-hex GPG key id: reaches gpg/git argv, so hex-only is enforced. */
    ctx.accounts[0].gpg_enabled = true;
    strncpy(ctx.accounts[0].gpg_key_id, "DEADBEEF;id", sizeof(ctx.accounts[0].gpg_key_id) - 1);
    CHECK_EQ_INT(config_validate(&ctx), -1);

    /* And the same gates hold on the add path (the API accounts.c uses). */
    account_t bad;
    gitswitch_ctx_t fresh;
    memset(&fresh, 0, sizeof(fresh));
    fill_account(&bad, 1, "work", "w@x.com", "d");
    bad.gpg_enabled = true;
    strncpy(bad.gpg_key_id, "$(rm -rf ~)", sizeof(bad.gpg_key_id) - 1);
    CHECK_EQ_INT(config_add_account(&fresh, &bad), -1);
    CHECK_EQ_INT(fresh.account_count, 0);
}

/* ---- duplicate name/id guards (isolation is keyed by them) --------------- */

TEST(dup_name_id_rejected_on_load) {
    /* Two accounts sharing a name would share one GNUPGHOME (<base>/<name>)
     * and one ssh-agent.<name>.sock — the isolation would silently collapse.
     * The load path must keep only the FIRST and count the rest as skipped
     * (so config_save refuses to rewrite and erase them). Matching is
     * case-insensitive: the derived paths land on case-insensitive
     * filesystems too. */
    const char *cfg =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"Alice\"\n"
        "email = \"first@x.com\"\n"
        "[accounts.2]\n"
        "name = \"alice\"\n"          /* case-insensitive dup of accounts.1 */
        "email = \"second@x.com\"\n"
        "[accounts.3]\n"
        "name = \"bob\"\n"
        "email = \"b@x.com\"\n";
    char dir[128], path[256];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 2);
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 1);
    if (ctx.account_count == 2) {
        /* First occurrence wins, byte-for-byte. */
        CHECK_STR_EQ(ctx.accounts[0].name, "Alice");
        CHECK_STR_EQ(ctx.accounts[0].email, "first@x.com");
        CHECK_STR_EQ(ctx.accounts[1].name, "bob");
    }

    /* Duplicate ids cannot even be spelled in a file anymore (a repeated
     * [accounts.1] merges into one section; non-canonical alias spellings are
     * rejected — see load_skips_leading_zero_id_section). The id guard is
     * enforced at the API every mutating command uses: */
    gitswitch_ctx_t api;
    account_t a;
    memset(&api, 0, sizeof(api));
    fill_account(&a, 1, "work", "w@x.com", "d");
    CHECK_EQ_INT(config_add_account(&api, &a), 0);
    fill_account(&a, 1, "other", "o@x.com", "d");   /* same id, new name */
    CHECK_EQ_INT(config_add_account(&api, &a), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_ACCOUNT_EXISTS);
    fill_account(&a, 2, "WORK", "o@x.com", "d");    /* new id, dup name (case) */
    CHECK_EQ_INT(config_add_account(&api, &a), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_ACCOUNT_EXISTS);
    fill_account(&a, 2, "other", "o@x.com", "d");   /* both unique: fine */
    CHECK_EQ_INT(config_add_account(&api, &a), 0);
    CHECK_EQ_INT(api.account_count, 2);
}

/* ---- AR-03 M8: unknown sections must block (and survive) a rewrite ------- */

TEST(unknown_section_blocks_rewrite_and_is_preserved) {
    /* A typo'd [account.3] (or any custom section) is invisible to
     * config_save's rebuild — pre-fix it was not counted at load, so the
     * refuse-to-rewrite guard read zero, config_save returned 0, and the
     * section was permanently deleted by the very next save. */
    const char *cfg =
        "[settings]\n"
        "default_scope = \"local\"\n"
        "[accounts.1]\n"
        "name = \"alice\"\n"
        "email = \"a@b.com\"\n"
        "[account.3]\n"          /* typo: singular */
        "name = \"typod\"\n"
        "email = \"t@b.com\"\n";
    char dir[128], path[256], after[1024];
    gitswitch_ctx_t ctx;
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 1);              /* alice loads fine */
    CHECK_EQ_INT(ctx.unknown_sections_on_load, 1);   /* pre-fix: field absent */
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 0);

    /* Both gates must refuse, and the section must survive on disk. */
    CHECK_EQ_INT(config_check_rewritable(&ctx), -1);
    CHECK_EQ_INT(config_save(&ctx, path), -1);       /* pre-fix: 0 + erased */
    slurp(path, after, sizeof(after));
    CHECK(strstr(after, "[account.3]") != NULL);
    CHECK(strstr(after, "typod") != NULL);
}

/* ---- AR-03 M9(4): settings-only save must work around the skip guard ---- */

TEST(settings_only_save_records_active_and_preserves_sections) {
    /* One healthy account, one skipped (over-long name), one unknown section:
     * the full rewrite is (correctly) refused, but a switch to the healthy
     * account must still persist active_account — pre-fix the switch printed
     * success while active_account stayed stale, so the next boot's resume
     * restored the wrong identity. The write-back must keep BOTH problem
     * sections byte-for-byte-meaningful on disk. */
    char longname[300], cfg[1024], after[2048], hint[256], state[512];
    char dir[128], path[256];
    gitswitch_ctx_t ctx;

    memset(longname, 'N', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';
    snprintf(cfg, sizeof(cfg),
             "[settings]\n"
             "default_scope = \"local\"\n"
             "[accounts.1]\n"
             "name = \"alice\"\n"
             "email = \"a@b.com\"\n"
             "[accounts.2]\n"
             "name = \"%s\"\n"
             "email = \"long@b.com\"\n"
             "[account.3]\n"
             "name = \"typod\"\n",
             longname);
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(path, sizeof(path), "%s/accounts.toml", dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", dir);
    CHECK_EQ_INT(write_config(path, cfg, strlen(cfg)), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 1);
    CHECK_EQ_INT(ctx.unknown_sections_on_load, 1);

    /* Simulate the switch's bookkeeping, then the targeted save. */
    strncpy(ctx.config.active_account, "alice", sizeof(ctx.config.active_account) - 1);
    CHECK_EQ_INT(config_save_active_account(&ctx, path), 0); /* succeeds where config_save refuses */

    slurp(path, after, sizeof(after));
    CHECK_STR_EQ(after, cfg); /* state-only persistence never replaces accounts */
    CHECK(slurp(hint, state, sizeof(state)) > 0);
    CHECK_STR_EQ(state, "none\nactive=alice\n");

    /* And the write-back result must load again with the same view. */
    gitswitch_ctx_t ctx2;
    memset(&ctx2, 0, sizeof(ctx2));
    CHECK_EQ_INT(config_load(&ctx2, path), 0);
    CHECK_EQ_INT(ctx2.account_count, 1);
    CHECK_STR_EQ(ctx2.config.active_account, "alice");
    CHECK_EQ_INT(ctx2.accounts_skipped_on_load, 1);
    CHECK_EQ_INT(ctx2.unknown_sections_on_load, 1);
}

/* ---- AR-03 T4: the resume-hint writer itself ----------------------------- */

TEST(resume_hint_reflects_account_runtime_needs) {
    /* config_update_resume_hint records the active account's boot-volatile
     * runtime needs; the shell snippet branches on this exact content, so a
     * wrong value reintroduces either the doomed per-shell ssh-add probe
     * (AR-02 #23) or a wrongly-skipped resume. Drive it through config_save
     * (its only caller) with HOME pointed at a scratch dir. */
    char dir[128], path[256], hint[512], buf[64];
    char old_home[512];
    const char *home_env = getenv("HOME");
    gitswitch_ctx_t ctx;

    snprintf(old_home, sizeof(old_home), "%s", home_env ? home_env : "");
    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    CHECK_EQ_INT(setenv("HOME", dir, 1), 0);

    /* The hint lives in <config_dir>; create it like config_init would. */
    snprintf(path, sizeof(path), "%s/.config", dir);
    CHECK_EQ_INT(mkdir(path, 0700), 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch", dir);
    CHECK_EQ_INT(mkdir(path, 0700), 0);
    snprintf(hint, sizeof(hint), "%s/.config/gitswitch/.resume-hint", dir);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", dir);

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&ctx.accounts[0], 1, "alice", "a@b.com", "day job");
    ctx.account_count = 1;
    strncpy(ctx.config.active_account, "alice", sizeof(ctx.config.active_account) - 1);

    /* Identity-only: no boot-volatile state, the snippet must not probe. */
    CHECK_EQ_INT(config_save(&ctx, path), 0);
    CHECK(slurp(hint, buf, sizeof(buf)) > 0);
    CHECK_STR_EQ(buf, "none\nactive=alice\n");

    /* SSH-only. */
    ctx.accounts[0].ssh_enabled = true;
    strncpy(ctx.accounts[0].ssh_key_path, "/tmp/id_fake",
            sizeof(ctx.accounts[0].ssh_key_path) - 1);
    CHECK_EQ_INT(config_save(&ctx, path), 0);
    slurp(hint, buf, sizeof(buf));
    CHECK_STR_EQ(buf, "ssh\nactive=alice\n");

    /* SSH + GPG. */
    ctx.accounts[0].gpg_enabled = true;
    strncpy(ctx.accounts[0].gpg_key_id, "ABCDEF0123456789",
            sizeof(ctx.accounts[0].gpg_key_id) - 1);
    CHECK_EQ_INT(config_save(&ctx, path), 0);
    slurp(hint, buf, sizeof(buf));
    CHECK_STR_EQ(buf, "ssh gpg\nactive=alice\n");

    /* GPG-only. */
    ctx.accounts[0].ssh_enabled = false;
    ctx.accounts[0].ssh_key_path[0] = '\0';
    CHECK_EQ_INT(config_save(&ctx, path), 0);
    slurp(hint, buf, sizeof(buf));
    CHECK_STR_EQ(buf, "gpg\nactive=alice\n");

    /* An unknown active account is never advertised as a successful durable
     * identity; retain the last coherent state instead. */
    strncpy(ctx.config.active_account, "ghost", sizeof(ctx.config.active_account) - 1);
    CHECK_EQ_INT(config_save(&ctx, path), -1);
    slurp(hint, buf, sizeof(buf));
    CHECK_STR_EQ(buf, "gpg\nactive=alice\n");

    /* Cleared active account: install the explicit inactive tombstone. This
     * fixture builds a synthetic context (including a fake GPG selector)
     * rather than loading it, so use the full-save path; active-only saves of
     * an existing document are intentionally bound to a loaded generation. */
    ctx.config.active_account[0] = '\0';
    CHECK_EQ_INT(config_save(&ctx, path), 0);
    slurp(hint, buf, sizeof(buf));
    CHECK_STR_EQ(buf, "none\ninactive=v1\n");

    if (old_home[0]) setenv("HOME", old_home, 1); else unsetenv("HOME");
}

TEST(resume_hint_refuses_unsafe_nodes_and_replaces_regular_file_atomically) {
    char home[128], saved_home[512], dotconfig[256], config_dir[512];
    char path[640], hint[640], victim[640], buf[64];
    struct stat before, after;
    gitswitch_ctx_t ctx;
    DIR *stream;
    struct dirent *entry;
    int leaked_temps = 0;

    save_home_env(saved_home, sizeof(saved_home));
    CHECK_EQ_INT(make_scratch_dir(home, sizeof(home)), 0);
    snprintf(dotconfig, sizeof(dotconfig), "%s/.config", home);
    snprintf(config_dir, sizeof(config_dir), "%s/gitswitch", dotconfig);
    snprintf(path, sizeof(path), "%s/accounts.toml", config_dir);
    snprintf(hint, sizeof(hint), "%s/.resume-hint", config_dir);
    snprintf(victim, sizeof(victim), "%s/hint-victim", home);
    CHECK_EQ_INT(mkdir(dotconfig, 0700), 0);
    CHECK_EQ_INT(mkdir(config_dir, 0700), 0);
    CHECK_EQ_INT(write_config(victim, "victim-content\n", 15), 0);
    CHECK_EQ_INT(symlink(victim, hint), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&ctx.accounts[0], 1, "alice", "a@b.com", "day job");
    ctx.account_count = 1;
    strncpy(ctx.config.active_account, "alice",
            sizeof(ctx.config.active_account) - 1);

    /* The resume hint is required commit state as of AR-07 T5. Refusing an
     * unsafe node must now make the save truthful/nonzero while preserving the
     * node and its target exactly. */
    CHECK_EQ_INT(config_save(&ctx, path), -1);
    CHECK(slurp(victim, buf, sizeof(buf)) > 0);
    CHECK_STR_EQ(buf, "victim-content\n"); /* pre-fix: truncated to none */
    CHECK_EQ_INT(lstat(hint, &after), 0);
    CHECK(S_ISLNK(after.st_mode));

    CHECK_EQ_INT(unlink(hint), 0);
    CHECK_EQ_INT(mkfifo(hint, 0600), 0);
    CHECK_EQ_INT(config_save(&ctx, path), -1); /* never opens/blocks on FIFO */
    CHECK_EQ_INT(lstat(hint, &after), 0);
    CHECK(S_ISFIFO(after.st_mode));

    CHECK_EQ_INT(unlink(hint), 0);
    CHECK_EQ_INT(write_config(hint, "unsafe\n", 7), 0);
    CHECK_EQ_INT(chmod(hint, 0660), 0);
    CHECK_EQ_INT(config_save(&ctx, path), -1);
    CHECK(slurp(hint, buf, sizeof(buf)) > 0);
    CHECK_STR_EQ(buf, "unsafe\n");
    CHECK_EQ_INT(lstat(hint, &after), 0);
    CHECK_EQ_INT((long)(after.st_mode & 0777), 0660);

    /* A safe existing marker is replaced, not truncated in place: readers
     * see either complete old or complete new content, never a partial file. */
    CHECK_EQ_INT(write_config(hint, "none\n", 5), 0);
    CHECK_EQ_INT(lstat(hint, &before), 0);
    CHECK_EQ_INT(config_save(&ctx, path), 0);
    CHECK_EQ_INT(lstat(hint, &after), 0);
    CHECK(S_ISREG(after.st_mode));
    CHECK_EQ_INT((long)(after.st_mode & 0777), 0600);
    CHECK(before.st_dev != after.st_dev || before.st_ino != after.st_ino);
    CHECK(slurp(hint, buf, sizeof(buf)) > 0);
    CHECK_STR_EQ(buf, "none\nactive=alice\n");

    stream = opendir(config_dir);
    CHECK(stream != NULL);
    if (stream) {
        while ((entry = readdir(stream)) != NULL) {
            if (strncmp(entry->d_name, ".resume-hint.tmp.", 17) == 0) {
                leaked_temps++;
            }
        }
        closedir(stream);
    }
    CHECK_EQ_INT(leaked_temps, 0);

    restore_home_env(saved_home);
}

/* ---- AR-03 M5 (config half): ssh_key length cap at the validation gate --- */

TEST(add_rejects_ssh_key_path_over_256_chars_api) {
    /* The loader skips accounts whose persisted ssh_key exceeds 256 chars, so
     * the programmatic add/update gate must refuse such a path up front —
     * pre-fix config_add_account accepted it (with an existing 0600 key), the
     * save succeeded, and the account vanished on the next invocation. */
    char dir[128], seg[130], dir_a[512], dir_b[1024], key[1300];
    gitswitch_ctx_t ctx;
    account_t a;

    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    memset(seg, 'd', 120);
    seg[120] = '\0';
    snprintf(dir_a, sizeof(dir_a), "%s/a%s", dir, seg);
    CHECK_EQ_INT(mkdir(dir_a, 0700), 0);
    snprintf(dir_b, sizeof(dir_b), "%s/b%s", dir_a, seg);
    CHECK_EQ_INT(mkdir(dir_b, 0700), 0);
    snprintf(key, sizeof(key), "%s/id_long", dir_b);
    CHECK_EQ_INT(write_config(key, "KEY", 3), 0); /* creates it 0600 */
    CHECK((int)strlen(key) > 256);

    memset(&ctx, 0, sizeof(ctx));
    fill_account(&a, 1, "longkey", "l@x.com", "d");
    a.ssh_enabled = true;
    strncpy(a.ssh_key_path, key, sizeof(a.ssh_key_path) - 1);
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1); /* pre-fix: 0 */
    CHECK_EQ_INT(ctx.account_count, 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_ACCOUNT_INVALID);
}

/* AR-08 L5 integration: a caller may repair a schema-skipped document in
 * memory and persist it. Revalidation must clear the stale visibility state
 * before the repaired document is written and loaded through config.c. */
TEST(repaired_overlong_ssh_key_writes_and_loads_without_stale_skip) {
    static toml_document_t doc;
    char dir[128];
    char path[256];
    char key[256];
    char longpath[302];
    char src[1024];
    char visible_name[64] = "";
    gitswitch_ctx_t ctx;

    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    CHECK(snprintf(path, sizeof(path), "%s/accounts.toml", dir) <
          (int)sizeof(path));
    CHECK(snprintf(key, sizeof(key), "%s/id_repaired", dir) <
          (int)sizeof(key));
    CHECK_EQ_INT(write_config(
                     key,
                     "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n",
                     sizeof("-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n") - 1),
                 0);

    longpath[0] = '/';
    memset(longpath + 1, 'b', sizeof(longpath) - 2);
    longpath[sizeof(longpath) - 1] = '\0';
    CHECK(snprintf(src, sizeof(src),
                   "[settings]\n"
                   "default_scope = \"local\"\n"
                   "[accounts.1]\n"
                   "name = \"repaired\"\n"
                   "email = \"repaired@example.com\"\n"
                   "ssh_key = \"%s\"\n",
                   longpath) < (int)sizeof(src));

    CHECK_EQ_INT(toml_parse_string(src, strlen(src), &doc), 0);
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.1", "name", visible_name,
                                 sizeof(visible_name)), -1);
    CHECK_EQ_INT(toml_set_string(&doc, "accounts.1", "ssh_key", key), 0);
    CHECK_EQ_INT(toml_validate_gitswitch_schema(&doc), 0);
    CHECK_EQ_INT(toml_get_string(&doc, "accounts.1", "name", visible_name,
                                 sizeof(visible_name)), 0);
    CHECK_STR_EQ(visible_name, "repaired");
    CHECK_EQ_INT(toml_write_file(&doc, path), 0);
    toml_cleanup_document(&doc);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, path), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
    CHECK_EQ_INT(ctx.accounts_skipped_on_load, 0);
    if (ctx.account_count == 1) {
        CHECK_STR_EQ(ctx.accounts[0].name, "repaired");
        CHECK_STR_EQ(ctx.accounts[0].ssh_key_path, key);
        CHECK(ctx.accounts[0].ssh_enabled);
    }
}

/* ---- AR-03 M6 follow-through: the write gate matches the read gate ------- */

TEST(add_rejects_values_that_cannot_roundtrip) {
    /* Since M6 toml_get_string FAILS on any value its sanitizer would alter
     * (quote, backslash, ...). The write side must refuse the same values,
     * or gitswitch persists a name/description its own next load cannot hand
     * back — the account it just created is then skipped with a warning. */
    gitswitch_ctx_t ctx;
    account_t a;
    memset(&ctx, 0, sizeof(ctx));

    fill_account(&a, 1, "Jane \"Work\"", "j@x.com", "d"); /* the M6 repro name */
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);       /* pre-fix: 0 */
    CHECK_EQ_INT(ctx.account_count, 0);

    fill_account(&a, 1, "jane", "j@x.com", "back\\slash desc");
    CHECK_EQ_INT(config_add_account(&ctx, &a), -1);       /* pre-fix: 0 */
    CHECK_EQ_INT(ctx.account_count, 0);

    /* Plain values (including multi-byte UTF-8) still pass. */
    fill_account(&a, 1, "jane", "j@x.com", "caf\xC3\xA9 desk");
    CHECK_EQ_INT(config_add_account(&ctx, &a), 0);
    CHECK_EQ_INT(ctx.account_count, 1);
}

/* AR-06 F46/F47: two saves in the same wall-clock second must not collide on
 * the one-second-granularity backup name. The second config_backup must still
 * succeed with a disambiguated name, leaving both backups on disk. */
TEST(back_to_back_backups_in_same_second_both_persist) {
    char dir[128], cfg[256];
    DIR *d;
    struct dirent *ent;
    int backups = 0;

    CHECK_EQ_INT(make_scratch_dir(dir, sizeof(dir)), 0);
    snprintf(cfg, sizeof(cfg), "%s/accounts.toml", dir);
    CHECK_EQ_INT(write_config(cfg, valid_config, strlen(valid_config)), 0);

    /* Same second (no sleep between): pre-fix the 2nd hit EEXIST and vanished. */
    CHECK_EQ_INT(config_backup(cfg), 0);
    CHECK_EQ_INT(config_backup(cfg), 0);

    d = opendir(dir);
    CHECK(d != NULL);
    if (d) {
        while ((ent = readdir(d)) != NULL) {
            if (strstr(ent->d_name, "accounts.toml.backup.")) backups++;
        }
        closedir(d);
    }
    CHECK_EQ_INT(backups, 2); /* both backups survive */
}

/* AR-06 F50: destructive resolution (remove/reset) accepts only an exact
 * id/name/email, never a substring or description match. */
TEST(destructive_resolution_refuses_substring) {
    gitswitch_ctx_t ctx;
    account_t a;
    memset(&ctx, 0, sizeof(ctx));

    fill_account(&a, 1, "work-old", "old@example.com", "primary");
    CHECK_EQ_INT(config_add_account(&ctx, &a), 0);
    fill_account(&a, 2, "personal", "me@example.com", "the work laptop");
    CHECK_EQ_INT(config_add_account(&ctx, &a), 0);

    /* Even an UNAMBIGUOUS substring is refused for destructive ops... */
    CHECK(config_find_account_destructive(&ctx, "person") == NULL); /* in "personal" */
    CHECK(config_find_account_destructive(&ctx, "laptop") == NULL); /* in a description */
    /* ...while the fuzzy resolver still accepts the unambiguous substring. */
    CHECK(config_find_account(&ctx, "person") != NULL);

    /* Exact id / name / email still resolve for destructive ops. */
    CHECK(config_find_account_destructive(&ctx, "1") != NULL);
    CHECK(config_find_account_destructive(&ctx, "work-old") != NULL);
    CHECK(config_find_account_destructive(&ctx, "me@example.com") != NULL);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(back_to_back_backups_in_same_second_both_persist);
    RUN_TEST(destructive_resolution_refuses_substring);
    RUN_TEST(load_accepts_regular_file);
    RUN_TEST(load_rejects_file_growth_after_prefix_read);
    RUN_TEST(system_scope_is_rejected_before_admission_or_persistence);
    RUN_TEST(zero_account_id_is_rejected_before_mutation_or_persistence);
    RUN_TEST(current_pointer_rebinds_after_direct_array_compaction);
    RUN_TEST(failed_reload_preserves_complete_context);
    RUN_TEST(reload_reconciles_current_account_from_runtime_or_saved_state);
    RUN_TEST(load_rejects_symlinked_config);
    RUN_TEST(config_init_rejects_symlinked_final_directory_without_mutation);
    RUN_TEST(config_init_rejects_nondirectory_final_components);
    RUN_TEST(config_init_secures_real_or_absent_final_directory);
    RUN_TEST(config_get_path_uses_home_or_passwd_without_filesystem_mutation);
    RUN_TEST(config_lock_rejects_symlink_fifo_and_unsafe_mode);
    RUN_TEST(config_lock_release_preserves_reused_fd_and_retires_context);
    RUN_TEST(config_lock_survives_post_acquisition_namespace_replacement);
    RUN_TEST(config_init_preserves_symlinked_parent_policy);
    RUN_TEST(save_refuses_symlinked_config_path);
    RUN_TEST(backup_refuses_symlinked_source);
    RUN_TEST(save_and_reload_regular_path_roundtrip);
    RUN_TEST(account_model_invariant_blocks_lossy_states_before_mutation);
    RUN_TEST(account_model_admitted_states_roundtrip_exactly);
    RUN_TEST(ssh_hostname_load_save_and_shared_destination_roundtrip);
    RUN_TEST(legacy_literal_ssh_host_falls_back_and_is_canonicalized);
    RUN_TEST(legacy_wildcard_alias_requires_explicit_canonical_hostname);
    RUN_TEST(ssh_hostname_schema_and_api_reject_unsafe_values);
    RUN_TEST(find_account_rejects_out_of_range_and_noncanonical_ids);
    RUN_TEST(load_skips_leading_zero_id_section);
    RUN_TEST(load_counts_unknown_keys_in_recognized_sections);
    RUN_TEST(load_accepts_only_modeled_keys);
    RUN_TEST(load_skips_out_of_range_id_section);
    RUN_TEST(load_counts_overlong_name_as_skipped_and_save_preserves_it);
    RUN_TEST(config_save_registers_and_unregisters_its_temp);
    RUN_TEST(load_strips_cr_from_description);
    RUN_TEST(load_rejects_raw_c1_byte_in_file);
    RUN_TEST(add_rejects_c1_and_malformed_utf8_in_name);
    RUN_TEST(add_rejects_escape_in_description);
    RUN_TEST(config_validate_rejects_hostile_account);
    RUN_TEST(dup_name_id_rejected_on_load);
    RUN_TEST(unknown_section_blocks_rewrite_and_is_preserved);
    RUN_TEST(settings_only_save_records_active_and_preserves_sections);
    RUN_TEST(resume_hint_reflects_account_runtime_needs);
    RUN_TEST(resume_hint_refuses_unsafe_nodes_and_replaces_regular_file_atomically);
    RUN_TEST(add_rejects_ssh_key_path_over_256_chars_api);
    RUN_TEST(repaired_overlong_ssh_key_writes_and_loads_without_stale_skip);
    RUN_TEST(add_rejects_values_that_cannot_roundtrip);
TEST_MAIN_END()
