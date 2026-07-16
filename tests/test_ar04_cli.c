/* AR-04 CLI regressions for reset truthfulness and combined runtime resume.
 *
 * main.c is not linked into test binaries, so these cases execute the built
 * gitswitch binary in isolated HOME/XDG_RUNTIME_DIR fixtures. */

#include "test.h"
#include "error.h"
#include "publication.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static char g_bin[PATH_MAX];

#define AR04_CLI_WORK_INCARNATION \
    "4141414141414141414141414141414141414141414141414141414141414141"
#define AR04_CLI_OTHER_INCARNATION \
    "4242424242424242424242424242424242424242424242424242424242424242"

static int resolve_binary(void) {
    const char *bin = getenv("GITSWITCH_BIN");

    if (!bin || !*bin) {
        bin = "build/bin/gitswitch";
    }
    if (!realpath(bin, g_bin) || access(g_bin, X_OK) != 0) {
        fprintf(stderr, "test_ar04_cli: executable not found at %s\n", bin);
        return -1;
    }
    return 0;
}

static int make_temp_dir(char *buf, size_t size) {
    if (snprintf(buf, size, "/tmp/gitswitch-ar04-XXXXXX") < 0 || !ts_mkdtemp(buf)) {
        return -1;
    }
    return 0;
}

static void remove_tree(const char *path) {
    char cmd[PATH_MAX + 32];
    int status;

    if (!path || !*path || strchr(path, '\'')) {
        return;
    }
    if (snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path) < 0) {
        return;
    }
    status = system(cmd);
    (void)status;
}

static int mkdir_private(const char *path) {
    if (mkdir(path, 0700) != 0 && errno != EEXIST) {
        return -1;
    }
    return chmod(path, 0700);
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

static int canonical_existing_path(const char *path, char *dest,
                                   size_t dest_size) {
    char resolved[PATH_MAX];
    size_t length;

    if (!path || !dest || dest_size == 0 || !realpath(path, resolved)) {
        return -1;
    }
    length = strlen(resolved);
    if (length >= dest_size) return -1;
    memcpy(dest, resolved, length + 1U);
    return 0;
}

static int create_live_ssh_socket(const char *runtime, char *socket_path,
                                  size_t socket_size, char *current_path,
                                  size_t current_size) {
    char dir[PATH_MAX];
    struct sockaddr_un addr;
    int fd;

    if (join_path(dir, sizeof(dir), runtime, "/gitswitch-ssh") != 0 ||
        join_path(socket_path, socket_size, runtime,
                  "/gitswitch-ssh/ssh-agent.work.sock") != 0 ||
        join_path(current_path, current_size, runtime,
                  "/gitswitch-ssh/current.sock") != 0 ||
        strlen(socket_path) >= sizeof(addr.sun_path) ||
        mkdir_private(dir) != 0) {
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, socket_path, strlen(socket_path) + 1);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        symlink(socket_path, current_path) != 0) {
        close(fd);
        unlink(socket_path);
        unlink(current_path);
        return -1;
    }
    return fd;
}

static int write_text(const char *path, const char *text, mode_t mode) {
    FILE *f = fopen(path, "w");

    if (!f) {
        return -1;
    }
    if (fputs(text, f) == EOF || fclose(f) != 0) {
        return -1;
    }
    return chmod(path, mode);
}

static int write_all(int fd, const void *data, size_t length) {
    const unsigned char *cursor = data;
    size_t written = 0U;

    while (written < length) {
        ssize_t result = write(fd, cursor + written, length - written);

        if (result > 0) {
            written += (size_t)result;
        } else if (result < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

/* Successful reset fixtures carry the same immutable attribution a completed
 * switch would have persisted. These accounts are genuinely credentialless,
 * so destination plus exact post-generation is the complete authority. */
static int seed_account_publication(const char *home, uint32_t account_id,
                                    const char *incarnation) {
    static const char git_body[] =
        "[fixture]\n"
        "\tgeneration = ar04-cli\n";
    static const char state_header[] = "none\nactive=work\n";
    char git_path[PATH_MAX];
    char state_path[PATH_MAX];
    publication_ledger_t ledger;
    unsigned char *tail = NULL;
    size_t tail_length = 0U;
    struct stat parent_st;
    struct stat config_st;
    int fd = -1;
    int result = -1;

    if (!home ||
        snprintf(git_path, sizeof(git_path), "%s/.gitconfig", home) < 0 ||
        snprintf(state_path, sizeof(state_path),
                 "%s/.config/gitswitch/.resume-hint", home) < 0 ||
        write_text(git_path, git_body, 0600) != 0 ||
        stat(home, &parent_st) != 0 || stat(git_path, &config_st) != 0) {
        return -1;
    }

    publication_ledger_init(&ledger);
    {
        publication_record_t record;

        publication_record_init(&record);
        record.account_id = account_id;
        record.scope = PUBLICATION_SCOPE_GLOBAL;
        record.state = PUBLICATION_STATE_PUBLISHED;
        record.capabilities = PUBLICATION_CAP_DESTINATION |
                              PUBLICATION_CAP_POST_GENERATION;
        if (!incarnation ||
            safe_strncpy(record.account_incarnation, incarnation,
                         sizeof(record.account_incarnation)) != 0 ||
            safe_strncpy(record.config_path, git_path,
                         sizeof(record.config_path)) != 0) {
            goto cleanup;
        }
        publication_identity_from_stat(&record.config_parent, &parent_st);
        publication_identity_from_stat(&record.post_config, &config_st);
        if (publication_record_validate(&record) != 0 ||
            publication_ledger_upsert(&ledger, &record) != 0) {
            goto cleanup;
        }
    }
    if (publication_ledger_serialize(&ledger, &tail, &tail_length) != 0) {
        goto cleanup;
    }

    fd = open(state_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 ||
        write_all(fd, state_header, sizeof(state_header) - 1U) != 0 ||
        write_all(fd, tail, tail_length) != 0 || fsync(fd) != 0 ||
        close(fd) != 0) {
        if (fd >= 0) (void)close(fd);
        fd = -1;
        goto cleanup;
    }
    fd = -1;
    result = 0;

cleanup:
    if (fd >= 0) (void)close(fd);
    if (tail) {
        memset(tail, 0, tail_length);
        free(tail);
    }
    publication_ledger_clear(&ledger);
    return result;
}

static const char *slurp(const char *path, char *buf, size_t size) {
    FILE *f;
    size_t n;

    if (!buf || size == 0) {
        return "";
    }
    buf[0] = '\0';
    f = fopen(path, "r");
    if (!f) {
        return buf;
    }
    n = fread(buf, 1, size - 1, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

/* AR-06 F33: keep a crash/signal-kill distinguishable from an ordinary
 * nonzero exit — -(1000+signal) for abnormal termination, -1 for a system()
 * failure — so a broken binary can never satisfy a negative-path witness. */
static int run_shell(const char *cmd) {
    int status = system(cmd);

    if (status == -1) {
        return -1;
    }
    if (!WIFEXITED(status)) {
        return WIFSIGNALED(status) ? -(1000 + WTERMSIG(status)) : -1;
    }
    return WEXITSTATUS(status);
}

static size_t substring_count(const char *haystack, const char *needle) {
    size_t count = 0;
    size_t needle_len = strlen(needle);

    if (needle_len == 0) {
        return 0;
    }
    while ((haystack = strstr(haystack, needle)) != NULL) {
        count++;
        haystack += needle_len;
    }
    return count;
}

static int write_active_config(const char *home) {
    char path[PATH_MAX];
    static const char body[] =
        "[settings]\n"
        "default_scope = \"global\"\n"
        "active_account = \"work\"\n"
        "\n"
        "[accounts.1]\n"
        "incarnation = \"" AR04_CLI_WORK_INCARNATION "\"\n"
        "name = \"work\"\n"
        "email = \"work@example.com\"\n"
        "preferred_scope = \"global\"\n";

    snprintf(path, sizeof(path), "%s/.config", home);
    if (mkdir_private(path) != 0) return -1;
    snprintf(path, sizeof(path), "%s/.config/gitswitch", home);
    if (mkdir_private(path) != 0) return -1;
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    if (write_text(path, body, 0600) != 0) return -1;
    return seed_account_publication(home, 1U,
                                    AR04_CLI_WORK_INCARNATION);
}

static int write_two_account_active_config(const char *home,
                                           uint32_t published_account_id,
                                           const char *published_incarnation) {
    char path[PATH_MAX];
    static const char body[] =
        "[settings]\n"
        "default_scope = \"global\"\n"
        "active_account = \"work\"\n"
        "\n"
        "[accounts.1]\n"
        "incarnation = \"" AR04_CLI_WORK_INCARNATION "\"\n"
        "name = \"work\"\n"
        "email = \"work@example.com\"\n"
        "preferred_scope = \"global\"\n"
        "\n"
        "[accounts.2]\n"
        "incarnation = \"" AR04_CLI_OTHER_INCARNATION "\"\n"
        "name = \"other\"\n"
        "email = \"other@example.com\"\n"
        "preferred_scope = \"global\"\n";

    snprintf(path, sizeof(path), "%s/.config", home);
    if (mkdir_private(path) != 0) return -1;
    snprintf(path, sizeof(path), "%s/.config/gitswitch", home);
    if (mkdir_private(path) != 0) return -1;
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    if (write_text(path, body, 0600) != 0) return -1;
    return seed_account_publication(home, published_account_id,
                                    published_incarnation);
}

static void assert_retry_state_preserved(const char *home) {
    char path[PATH_MAX];
    char contents[4096];

    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "active_account = \"work\"") != NULL);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/.resume-hint", home);
    CHECK(access(path, F_OK) == 0);
}

static int run_reset(const char *home, const char *runtime, const char *output) {
    char cmd[PATH_MAX * 4];

    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' -C -y reset "
             "</dev/null >'%s' 2>&1",
             home, runtime, g_bin, output);
    return run_shell(cmd);
}

static int run_targeted_reset(const char *home, const char *runtime,
                              const char *account, const char *output) {
    char cmd[PATH_MAX * 5];

    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' -C -y reset '%s' "
             "</dev/null >'%s' 2>&1",
             home, runtime, g_bin, account, output);
    return run_shell(cmd);
}

TEST(reset_ssh_failure_preserves_retry_state_and_attempts_gpg) {
    char home[PATH_MAX], runtime[PATH_MAX], path[PATH_MAX], target[PATH_MAX];
    char output[PATH_MAX], contents[8192];
    struct stat link_st;

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(write_active_config(home), 0);

    CHECK_EQ_INT(join_path(target, sizeof(target), runtime, "/foreign-ssh"), 0);
    CHECK_EQ_INT(mkdir_private(target), 0);
    CHECK_EQ_INT(join_path(path, sizeof(path), runtime, "/gitswitch-ssh"), 0);
    CHECK_EQ_INT(symlink(target, path), 0);

    /* A dangling GPG current link is a deterministic witness that the GPG
     * manager was still attempted after SSH failed: gpg_manager_reset lstat()s
     * it, sees a symlink, and unlinks it. Prove the LINK itself exists before
     * the run and is gone after — access() follows symlinks, so it returned
     * -1 for the dangling link whether or not the second manager ever ran,
     * making the old witness a tautology (AR-05 M6). */
    CHECK_EQ_INT(join_path(path, sizeof(path), runtime, "/gitswitch-gpg"), 0);
    CHECK_EQ_INT(mkdir_private(path), 0);
    CHECK_EQ_INT(join_path(path, sizeof(path), runtime,
                           "/gitswitch-gpg/current"), 0);
    CHECK_EQ_INT(symlink("missing", path), 0);
    CHECK_EQ_INT(lstat(path, &link_st), 0);
    CHECK(S_ISLNK(link_st.st_mode));

    CHECK_EQ_INT(join_path(output, sizeof(output), runtime, "/reset.out"), 0);
    CHECK(run_reset(home, runtime, output) != 0);
    assert_retry_state_preserved(home);
    errno = 0;
    CHECK(lstat(path, &link_st) != 0 && errno == ENOENT);
    slurp(output, contents, sizeof(contents));
    CHECK_EQ_INT(substring_count(contents, "gitswitch: SSH reset failed:"), 1);
    CHECK(strstr(contents, "Reset all gitswitch SSH/GPG state") == NULL);

    remove_tree(home);
    remove_tree(runtime);
}

TEST(reset_gpg_failure_preserves_retry_state) {
    char home[PATH_MAX], runtime[PATH_MAX], path[PATH_MAX], output[PATH_MAX];
    char contents[8192];

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(write_active_config(home), 0);
    CHECK_EQ_INT(join_path(path, sizeof(path), runtime, "/gitswitch-gpg"), 0);
    CHECK_EQ_INT(mkdir_private(path), 0);
    CHECK_EQ_INT(join_path(path, sizeof(path), runtime,
                           "/gitswitch-gpg/.lock"), 0);
    CHECK_EQ_INT(mkdir_private(path), 0);

    CHECK_EQ_INT(join_path(output, sizeof(output), runtime, "/reset.out"), 0);
    CHECK(run_reset(home, runtime, output) != 0);
    assert_retry_state_preserved(home);
    slurp(output, contents, sizeof(contents));
    CHECK_EQ_INT(substring_count(contents, "gitswitch: GPG reset failed:"), 1);
    CHECK(strstr(contents, "Reset all gitswitch SSH/GPG state") == NULL);

    remove_tree(home);
    remove_tree(runtime);
}

TEST(reset_reports_both_subsystem_failures_once) {
    char home[PATH_MAX], runtime[PATH_MAX], path[PATH_MAX], target[PATH_MAX];
    char output[PATH_MAX], contents[8192];

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(write_active_config(home), 0);
    CHECK_EQ_INT(join_path(target, sizeof(target), runtime, "/foreign-ssh"), 0);
    CHECK_EQ_INT(mkdir_private(target), 0);
    CHECK_EQ_INT(join_path(path, sizeof(path), runtime, "/gitswitch-ssh"), 0);
    CHECK_EQ_INT(symlink(target, path), 0);
    CHECK_EQ_INT(join_path(path, sizeof(path), runtime, "/gitswitch-gpg"), 0);
    CHECK_EQ_INT(mkdir_private(path), 0);
    CHECK_EQ_INT(join_path(path, sizeof(path), runtime,
                           "/gitswitch-gpg/.lock"), 0);
    CHECK_EQ_INT(mkdir_private(path), 0);

    CHECK_EQ_INT(join_path(output, sizeof(output), runtime, "/reset.out"), 0);
    CHECK(run_reset(home, runtime, output) != 0);
    assert_retry_state_preserved(home);
    slurp(output, contents, sizeof(contents));
    CHECK_EQ_INT(substring_count(contents, "gitswitch: SSH reset failed:"), 1);
    CHECK_EQ_INT(substring_count(contents, "gitswitch: GPG reset failed:"), 1);
    CHECK_EQ_INT(substring_count(contents, "gitswitch: reset failed; retry metadata was preserved"), 1);

    remove_tree(home);
    remove_tree(runtime);
}

TEST(targeted_reset_metadata_matches_active_account_scope) {
    char home[PATH_MAX], runtime[PATH_MAX], config[PATH_MAX];
    char hint[PATH_MAX], output[PATH_MAX], contents[8192];
    int reset_rc;

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(write_two_account_active_config(
                     home, 1U, AR04_CLI_WORK_INCARNATION), 0);
    CHECK_EQ_INT(join_path(config, sizeof(config), home,
                           "/.config/gitswitch/accounts.toml"), 0);
    CHECK_EQ_INT(join_path(hint, sizeof(hint), home,
                           "/.config/gitswitch/.resume-hint"), 0);
    CHECK_EQ_INT(join_path(output, sizeof(output), runtime, "/reset.out"), 0);

    /* Resetting the active account installs an authoritative inactive
     * tombstone; the legacy settings key may remain byte-identical but cannot
     * be resurrected on reload. Both account records remain. */
    reset_rc = run_targeted_reset(home, runtime, "work", output);
    CHECK_EQ_INT(reset_rc, 0);
    slurp(config, contents, sizeof(contents));
    CHECK(strstr(contents, "active_account = \"work\"") != NULL);
    CHECK(strstr(contents, "name = \"work\"") != NULL);
    CHECK(strstr(contents, "name = \"other\"") != NULL);
    slurp(hint, contents, sizeof(contents));
    CHECK(strncmp(contents, "none\ninactive=v1\n",
                  strlen("none\ninactive=v1\n")) == 0);
    CHECK(strstr(contents, "publications=v1\n") != NULL);

    /* Resetting an inactive account must not rewrite the active marker or its
     * exact retry hint. Recreate the starting document to exercise that arm. */
    CHECK_EQ_INT(write_two_account_active_config(
                     home, 2U, AR04_CLI_OTHER_INCARNATION), 0);
    reset_rc = run_targeted_reset(home, runtime, "other", output);
    CHECK_EQ_INT(reset_rc, 0);
    slurp(config, contents, sizeof(contents));
    CHECK(strstr(contents, "active_account = \"work\"") != NULL);
    slurp(hint, contents, sizeof(contents));
    CHECK(strncmp(contents, "none\nactive=work\n",
                  strlen("none\nactive=work\n")) == 0);
    CHECK(strstr(contents, "publications=v1\n") != NULL);

    remove_tree(home);
    remove_tree(runtime);
}

static int prepare_init_fixture(const char *home, const char *runtime,
                                char *snippet, size_t snippet_size,
                                char *shim_dir, size_t shim_size,
                                char *hint, size_t hint_size,
                                char *resume_log, size_t log_size) {
    char path[PATH_MAX];
    char cmd[PATH_MAX * 4];

    snprintf(path, sizeof(path), "%s/.config", home);
    if (mkdir_private(path) != 0) return -1;
    snprintf(path, sizeof(path), "%s/.config/gitswitch", home);
    if (mkdir_private(path) != 0) return -1;
    snprintf(hint, hint_size, "%s/.config/gitswitch/.resume-hint", home);
    snprintf(snippet, snippet_size, "%s/init.sh", runtime);
    snprintf(shim_dir, shim_size, "%s/shims", runtime);
    if (mkdir_private(shim_dir) != 0) return -1;
    snprintf(resume_log, log_size, "%s/resume.log", runtime);

    snprintf(path, sizeof(path), "%s/ssh-add", shim_dir);
    if (write_text(path,
                   "#!/bin/sh\nexit \"${GS_TEST_SSH_RC:-2}\"\n", 0700) != 0) {
        return -1;
    }
    snprintf(path, sizeof(path), "%s/gitswitch", shim_dir);
    if (write_text(path,
                   "#!/bin/sh\n"
                   "if [ \"$1\" = --resume-hint-probe ]; then exec \"$GS_REAL_BIN\" \"$@\"; fi\n"
                   "if [ \"$1\" = resume ]; then printf 'resume\\n' >>\"$GS_TEST_RESUME_LOG\"; fi\n"
                   "exit 0\n", 0700) != 0) {
        return -1;
    }

    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' init sh >'%s' 2>/dev/null",
             home, runtime, g_bin, snippet);
    return run_shell(cmd);
}

static int generate_init_snippet(const char *home, const char *runtime,
                                 const char *shell, const char *snippet) {
    char cmd[PATH_MAX * 6];

    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' '%s' init '%s' >'%s' 2>/dev/null",
             home, runtime, g_bin, shell, snippet);
    return run_shell(cmd);
}

static int count_resume_log(const char *resume_log) {
    char contents[256];
    const char *p;
    int count = 0;

    if (access(resume_log, F_OK) != 0) return 0;
    slurp(resume_log, contents, sizeof(contents));
    for (p = contents; *p; p++) {
        if (*p == '\n') count++;
    }
    return count;
}

static int evaluate_resume_case(const char *home, const char *runtime,
                                const char *snippet, const char *shim_dir,
                                const char *hint_path, const char *resume_log,
                                const char *hint_value, int ssh_rc,
                                int gpg_live) {
    char path[PATH_MAX];
    char cmd[PATH_MAX * 6];
    char hint_body[64];

    if (*hint_value == '\0') hint_body[0] = '\0';
    else snprintf(hint_body, sizeof(hint_body), "%s\n", hint_value);
    if (write_text(hint_path, hint_body, 0600) != 0) return -1;
    unlink(resume_log);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg", runtime);
    remove_tree(path);
    if (mkdir_private(path) != 0) return -1;
    if (gpg_live) {
        snprintf(path, sizeof(path), "%s/gitswitch-gpg/current", runtime);
        if (mkdir_private(path) != 0) return -1;
    }

    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' ENV=/dev/null "
             "PATH='%s:/usr/bin:/bin' GS_TEST_SSH_RC=%d "
             "GS_TEST_RESUME_LOG='%s' GS_REAL_BIN='%s' "
             "/bin/sh -ic \". '%s'\" "
             ">/dev/null 2>&1",
             home, runtime, shim_dir, ssh_rc, resume_log, g_bin, snippet);
    if (run_shell(cmd) != 0) return -1;
    return count_resume_log(resume_log);
}

static const char *find_fish_binary(void) {
    static const char *const candidates[] = {
        "/usr/bin/fish",
        "/usr/local/bin/fish",
        "/opt/homebrew/bin/fish"
    };
    size_t i;

    for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (access(candidates[i], X_OK) == 0) return candidates[i];
    }
    return NULL;
}

static int evaluate_fish_resume_case(const char *home, const char *runtime,
                                     const char *snippet,
                                     const char *shim_dir,
                                     const char *hint_path,
                                     const char *resume_log,
                                     const char *hint_value, int ssh_rc,
                                     int gpg_live, const char *fish_bin) {
    char path[PATH_MAX];
    char cmd[PATH_MAX * 6];
    char hint_body[64];

    if (*hint_value == '\0') hint_body[0] = '\0';
    else snprintf(hint_body, sizeof(hint_body), "%s\n", hint_value);
    if (write_text(hint_path, hint_body, 0600) != 0) return -1;
    unlink(resume_log);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg", runtime);
    remove_tree(path);
    if (mkdir_private(path) != 0) return -1;
    if (gpg_live) {
        snprintf(path, sizeof(path), "%s/gitswitch-gpg/current", runtime);
        if (mkdir_private(path) != 0) return -1;
    }

    snprintf(cmd, sizeof(cmd),
             "env HOME='%s' XDG_RUNTIME_DIR='%s' PATH='%s:/usr/bin:/bin' "
             "GS_TEST_SSH_RC=%d GS_TEST_RESUME_LOG='%s' GS_REAL_BIN='%s' "
             "'%s' --no-config -ic \"source '%s'\" >/dev/null 2>&1",
             home, runtime, shim_dir, ssh_rc, resume_log, g_bin, fish_bin,
             snippet);
    if (run_shell(cmd) != 0) return -1;
    return count_resume_log(resume_log);
}

TEST(combined_resume_hint_probes_both_resources_once) {
    char home[PATH_MAX], runtime[PATH_MAX], snippet[PATH_MAX], shims[PATH_MAX];
    char hint[PATH_MAX], log_path[PATH_MAX];

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_init_fixture(home, runtime, snippet, sizeof(snippet),
                                      shims, sizeof(shims), hint, sizeof(hint),
                                      log_path, sizeof(log_path)), 0);

    CHECK_EQ_INT(evaluate_resume_case(home, runtime, snippet, shims, hint, log_path,
                                      "none", 2, 0), 0);
    CHECK_EQ_INT(evaluate_resume_case(home, runtime, snippet, shims, hint, log_path,
                                      "ssh", 0, 0), 0);
    CHECK_EQ_INT(evaluate_resume_case(home, runtime, snippet, shims, hint, log_path,
                                      "ssh", 2, 1), 1);
    CHECK_EQ_INT(evaluate_resume_case(home, runtime, snippet, shims, hint, log_path,
                                      "gpg", 0, 1), 0);
    CHECK_EQ_INT(evaluate_resume_case(home, runtime, snippet, shims, hint, log_path,
                                      "gpg", 0, 0), 1);
    CHECK_EQ_INT(evaluate_resume_case(home, runtime, snippet, shims, hint, log_path,
                                      "ssh gpg", 0, 1), 0);
    CHECK_EQ_INT(evaluate_resume_case(home, runtime, snippet, shims, hint, log_path,
                                      "ssh gpg", 2, 1), 1);
    CHECK_EQ_INT(evaluate_resume_case(home, runtime, snippet, shims, hint, log_path,
                                      "ssh gpg", 0, 0), 1);
    CHECK_EQ_INT(evaluate_resume_case(home, runtime, snippet, shims, hint, log_path,
                                      "ssh gpg", 2, 0), 1);
    CHECK_EQ_INT(evaluate_resume_case(home, runtime, snippet, shims, hint, log_path,
                                      "legacy", 0, 1), 0);
    CHECK_EQ_INT(evaluate_resume_case(home, runtime, snippet, shims, hint, log_path,
                                      "legacy", 2, 1), 0);
    CHECK_EQ_INT(evaluate_resume_case(home, runtime, snippet, shims, hint, log_path,
                                      "legacy", 0, 0), 0);
    CHECK_EQ_INT(evaluate_resume_case(home, runtime, snippet, shims, hint, log_path,
                                      "", 0, 1), 0);
    CHECK_EQ_INT(evaluate_resume_case(home, runtime, snippet, shims, hint, log_path,
                                      "", 0, 0), 1);

    remove_tree(home);
    remove_tree(runtime);
}

TEST(fish_resume_hint_structure_uses_private_probe) {
    char home[PATH_MAX], runtime[PATH_MAX], fish_snippet[PATH_MAX];
    char contents[16384];

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(join_path(fish_snippet, sizeof(fish_snippet), runtime,
                           "/init.fish"), 0);
    CHECK_EQ_INT(generate_init_snippet(home, runtime, "fish", fish_snippet), 0);

    slurp(fish_snippet, contents, sizeof(contents));
    CHECK(strstr(contents, "case gpg") != NULL);
    CHECK(strstr(contents, "case 'ssh gpg'") != NULL);
    CHECK(strstr(contents, "command gitswitch --resume-hint-probe") != NULL);
    CHECK(strstr(contents, ".resume-hint") == NULL);
    CHECK(strstr(contents, "read -l __gitswitch_needs") == NULL);
    CHECK(strstr(contents, "case '*gpg*'") == NULL);

    remove_tree(home);
    remove_tree(runtime);
}

TEST(fish_combined_resume_hint_checks_both_resources_once) {
    char home[PATH_MAX], runtime[PATH_MAX], posix_snippet[PATH_MAX];
    char fish_snippet[PATH_MAX], shims[PATH_MAX], hint[PATH_MAX], log_path[PATH_MAX];
    const char *fish_bin = find_fish_binary();

    if (!fish_bin) {
        TS_SKIP("fish", "fish shell is unavailable");
    }
    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_init_fixture(home, runtime, posix_snippet,
                                      sizeof(posix_snippet), shims, sizeof(shims),
                                      hint, sizeof(hint), log_path,
                                      sizeof(log_path)), 0);
    CHECK_EQ_INT(join_path(fish_snippet, sizeof(fish_snippet), runtime,
                           "/init.fish"), 0);
    CHECK_EQ_INT(generate_init_snippet(home, runtime, "fish", fish_snippet), 0);

    CHECK_EQ_INT(evaluate_fish_resume_case(home, runtime, fish_snippet, shims, hint,
                                           log_path, "none", 2, 0,
                                           fish_bin), 0);
    CHECK_EQ_INT(evaluate_fish_resume_case(home, runtime, fish_snippet, shims, hint,
                                           log_path, "ssh", 0, 0,
                                           fish_bin), 0);
    CHECK_EQ_INT(evaluate_fish_resume_case(home, runtime, fish_snippet, shims, hint,
                                           log_path, "ssh", 2, 1,
                                           fish_bin), 1);
    CHECK_EQ_INT(evaluate_fish_resume_case(home, runtime, fish_snippet, shims, hint,
                                           log_path, "gpg", 0, 1,
                                           fish_bin), 0);
    CHECK_EQ_INT(evaluate_fish_resume_case(home, runtime, fish_snippet, shims, hint,
                                           log_path, "gpg", 0, 0,
                                           fish_bin), 1);
    CHECK_EQ_INT(evaluate_fish_resume_case(home, runtime, fish_snippet, shims, hint,
                                           log_path, "ssh gpg", 0, 1,
                                           fish_bin), 0);
    CHECK_EQ_INT(evaluate_fish_resume_case(home, runtime, fish_snippet, shims, hint,
                                           log_path, "ssh gpg", 2, 1,
                                           fish_bin), 1);
    CHECK_EQ_INT(evaluate_fish_resume_case(home, runtime, fish_snippet, shims, hint,
                                           log_path, "ssh gpg", 0, 0,
                                           fish_bin), 1);
    CHECK_EQ_INT(evaluate_fish_resume_case(home, runtime, fish_snippet, shims, hint,
                                           log_path, "ssh gpg", 2, 0,
                                           fish_bin), 1);
    CHECK_EQ_INT(evaluate_fish_resume_case(home, runtime, fish_snippet, shims, hint,
                                           log_path, "legacy", 0, 1,
                                           fish_bin), 0);
    CHECK_EQ_INT(evaluate_fish_resume_case(home, runtime, fish_snippet, shims, hint,
                                           log_path, "legacy", 2, 1,
                                           fish_bin), 0);
    CHECK_EQ_INT(evaluate_fish_resume_case(home, runtime, fish_snippet, shims, hint,
                                           log_path, "legacy", 0, 0,
                                           fish_bin), 0);
    CHECK_EQ_INT(evaluate_fish_resume_case(home, runtime, fish_snippet, shims, hint,
                                           log_path, "", 0, 1,
                                           fish_bin), 0);
    CHECK_EQ_INT(evaluate_fish_resume_case(home, runtime, fish_snippet, shims, hint,
                                           log_path, "", 0, 0,
                                           fish_bin), 1);

    remove_tree(home);
    remove_tree(runtime);
}

TEST(init_posix_snippet_is_quiet_noninteractive_and_exports_only_live_paths) {
    char home[PATH_MAX], runtime[PATH_MAX], snippet[PATH_MAX], shims[PATH_MAX];
    char canonical_runtime[PATH_MAX];
    char hint[PATH_MAX], log_path[PATH_MAX];
    char ssh_socket[PATH_MAX], ssh_current[PATH_MAX], gpg_base[PATH_MAX];
    char gpg_target[PATH_MAX], gpg_current[PATH_MAX], cmd[PATH_MAX * 9];
    int socket_fd = -1;

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(canonical_existing_path(runtime, canonical_runtime,
                                         sizeof(canonical_runtime)), 0);
    CHECK_EQ_INT(prepare_init_fixture(home, runtime, snippet, sizeof(snippet),
                                      shims, sizeof(shims), hint, sizeof(hint),
                                      log_path, sizeof(log_path)), 0);
    CHECK_EQ_INT(write_text(hint, "ssh gpg\n", 0600), 0);
    unlink(log_path);

    snprintf(cmd, sizeof(cmd),
             "env -u SSH_AUTH_SOCK -u GNUPGHOME HOME='%s' XDG_RUNTIME_DIR='%s' "
             "PATH='%s:/usr/bin:/bin' GS_TEST_SSH_RC=2 GS_TEST_RESUME_LOG='%s' "
             "/bin/sh -c \". '%s'; test -z \"\\${SSH_AUTH_SOCK+x}\"; "
             "test -z \"\\${GNUPGHOME+x}\"\" >/dev/null 2>&1",
             home, runtime, shims, log_path, snippet);
    CHECK_EQ_INT(run_shell(cmd), 0);
    CHECK(access(log_path, F_OK) != 0);

    /* SSH-only live state exports exactly SSH_AUTH_SOCK, without triggering
     * resume in a noninteractive shell. */
    /* Darwin spells the system /tmp alias as /private/tmp after the runtime
     * safety walk. Create and compare the live endpoints through that same
     * physical parent while still passing the caller's lexical XDG spelling. */
    socket_fd = create_live_ssh_socket(canonical_runtime, ssh_socket,
                                       sizeof(ssh_socket),
                                       ssh_current, sizeof(ssh_current));
    CHECK(socket_fd >= 0);
    if (socket_fd >= 0) {
        snprintf(cmd, sizeof(cmd),
                 "env -u SSH_AUTH_SOCK -u GNUPGHOME HOME='%s' "
                 "XDG_RUNTIME_DIR='%s' PATH='%s:/usr/bin:/bin' "
                 "GS_TEST_SSH_RC=2 GS_TEST_RESUME_LOG='%s' /bin/sh -c "
                 "\". '%s'; test \\\"\\$SSH_AUTH_SOCK\\\" = '%s'; "
                 "test -z \\\"\\${GNUPGHOME+x}\\\"\" >/dev/null 2>&1",
                 home, runtime, shims, log_path, snippet, ssh_current);
        CHECK_EQ_INT(run_shell(cmd), 0);
        CHECK(access(log_path, F_OK) != 0);
        CHECK_EQ_INT(close(socket_fd), 0);
        socket_fd = -1;
        CHECK_EQ_INT(unlink(ssh_current), 0);
        CHECK_EQ_INT(unlink(ssh_socket), 0);
    }

    /* GPG-only live state exports exactly GNUPGHOME. */
    CHECK_EQ_INT(join_path(gpg_base, sizeof(gpg_base), canonical_runtime,
                           "/gitswitch-gpg"), 0);
    CHECK_EQ_INT(join_path(gpg_target, sizeof(gpg_target), canonical_runtime,
                           "/gitswitch-gpg/work"), 0);
    CHECK_EQ_INT(join_path(gpg_current, sizeof(gpg_current), canonical_runtime,
                           "/gitswitch-gpg/current"), 0);
    CHECK_EQ_INT(mkdir_private(gpg_base), 0);
    CHECK_EQ_INT(mkdir_private(gpg_target), 0);
    CHECK_EQ_INT(symlink(gpg_target, gpg_current), 0);
    snprintf(cmd, sizeof(cmd),
             "env -u SSH_AUTH_SOCK -u GNUPGHOME HOME='%s' "
             "XDG_RUNTIME_DIR='%s' PATH='%s:/usr/bin:/bin' "
             "GS_TEST_SSH_RC=2 GS_TEST_RESUME_LOG='%s' /bin/sh -c "
             "\". '%s'; test -z \\\"\\${SSH_AUTH_SOCK+x}\\\"; "
             "test \\\"\\$GNUPGHOME\\\" = '%s'\" >/dev/null 2>&1",
             home, runtime, shims, log_path, snippet, gpg_current);
    CHECK_EQ_INT(run_shell(cmd), 0);
    CHECK(access(log_path, F_OK) != 0);

    if (socket_fd >= 0) close(socket_fd);

    remove_tree(home);
    remove_tree(runtime);
}

TEST(init_fish_snippet_is_quiet_noninteractive_and_exports_only_live_paths) {
    char home[PATH_MAX], runtime[PATH_MAX], posix_snippet[PATH_MAX];
    char canonical_runtime[PATH_MAX];
    char fish_snippet[PATH_MAX], shims[PATH_MAX], hint[PATH_MAX], log_path[PATH_MAX];
    char ssh_socket[PATH_MAX], ssh_current[PATH_MAX], gpg_base[PATH_MAX];
    char gpg_target[PATH_MAX], gpg_current[PATH_MAX], cmd[PATH_MAX * 9];
    const char *fish_bin = find_fish_binary();
    int socket_fd = -1;

    if (!fish_bin) {
        TS_SKIP("fish", "fish shell is unavailable");
    }
    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(canonical_existing_path(runtime, canonical_runtime,
                                         sizeof(canonical_runtime)), 0);
    CHECK_EQ_INT(prepare_init_fixture(home, runtime, posix_snippet,
                                      sizeof(posix_snippet), shims, sizeof(shims),
                                      hint, sizeof(hint), log_path,
                                      sizeof(log_path)), 0);
    CHECK_EQ_INT(join_path(fish_snippet, sizeof(fish_snippet), runtime,
                           "/init.fish"), 0);
    CHECK_EQ_INT(generate_init_snippet(home, runtime, "fish", fish_snippet), 0);
    CHECK_EQ_INT(write_text(hint, "ssh gpg\n", 0600), 0);
    unlink(log_path);

    snprintf(cmd, sizeof(cmd),
             "env -u SSH_AUTH_SOCK -u GNUPGHOME HOME='%s' "
             "XDG_RUNTIME_DIR='%s' PATH='%s:/usr/bin:/bin' "
             "GS_TEST_SSH_RC=2 GS_TEST_RESUME_LOG='%s' "
             "'%s' --no-config -c \"source '%s'; "
             "not set -q SSH_AUTH_SOCK; and not set -q GNUPGHOME\" "
             ">/dev/null 2>&1",
             home, runtime, shims, log_path, fish_bin, fish_snippet);
    CHECK_EQ_INT(run_shell(cmd), 0);
    CHECK(access(log_path, F_OK) != 0);

    socket_fd = create_live_ssh_socket(canonical_runtime, ssh_socket,
                                       sizeof(ssh_socket),
                                       ssh_current, sizeof(ssh_current));
    CHECK(socket_fd >= 0);
    if (socket_fd >= 0) {
        snprintf(cmd, sizeof(cmd),
                 "env -u SSH_AUTH_SOCK -u GNUPGHOME HOME='%s' "
                 "XDG_RUNTIME_DIR='%s' PATH='%s:/usr/bin:/bin' "
                 "GS_TEST_SSH_RC=2 GS_TEST_RESUME_LOG='%s' "
                 "'%s' --no-config -c \"source '%s'; "
                 "test \\\"\\$SSH_AUTH_SOCK\\\" = '%s'; "
                 "and not set -q GNUPGHOME\" >/dev/null 2>&1",
                 home, runtime, shims, log_path, fish_bin, fish_snippet,
                 ssh_current);
        CHECK_EQ_INT(run_shell(cmd), 0);
        CHECK(access(log_path, F_OK) != 0);
        CHECK_EQ_INT(close(socket_fd), 0);
        socket_fd = -1;
        CHECK_EQ_INT(unlink(ssh_current), 0);
        CHECK_EQ_INT(unlink(ssh_socket), 0);
    }

    CHECK_EQ_INT(join_path(gpg_base, sizeof(gpg_base), canonical_runtime,
                           "/gitswitch-gpg"), 0);
    CHECK_EQ_INT(join_path(gpg_target, sizeof(gpg_target), canonical_runtime,
                           "/gitswitch-gpg/work"), 0);
    CHECK_EQ_INT(join_path(gpg_current, sizeof(gpg_current), canonical_runtime,
                           "/gitswitch-gpg/current"), 0);
    CHECK_EQ_INT(mkdir_private(gpg_base), 0);
    CHECK_EQ_INT(mkdir_private(gpg_target), 0);
    CHECK_EQ_INT(symlink(gpg_target, gpg_current), 0);
    snprintf(cmd, sizeof(cmd),
             "env -u SSH_AUTH_SOCK -u GNUPGHOME HOME='%s' "
             "XDG_RUNTIME_DIR='%s' PATH='%s:/usr/bin:/bin' "
             "GS_TEST_SSH_RC=2 GS_TEST_RESUME_LOG='%s' "
             "'%s' --no-config -c \"source '%s'; "
             "not set -q SSH_AUTH_SOCK; and "
             "test \\\"\\$GNUPGHOME\\\" = '%s'\" >/dev/null 2>&1",
             home, runtime, shims, log_path, fish_bin, fish_snippet,
             gpg_current);
    CHECK_EQ_INT(run_shell(cmd), 0);
    CHECK(access(log_path, F_OK) != 0);

    if (socket_fd >= 0) close(socket_fd);
    remove_tree(home);
    remove_tree(runtime);
}

TEST_MAIN_BEGIN()
    if (resolve_binary() != 0) {
        return 1;
    }
    RUN_TEST(reset_ssh_failure_preserves_retry_state_and_attempts_gpg);
    RUN_TEST(reset_gpg_failure_preserves_retry_state);
    RUN_TEST(reset_reports_both_subsystem_failures_once);
    RUN_TEST(targeted_reset_metadata_matches_active_account_scope);
    RUN_TEST(combined_resume_hint_probes_both_resources_once);
    RUN_TEST(fish_resume_hint_structure_uses_private_probe);
    RUN_TEST(fish_combined_resume_hint_checks_both_resources_once);
    RUN_TEST(init_posix_snippet_is_quiet_noninteractive_and_exports_only_live_paths);
    RUN_TEST(init_fish_snippet_is_quiet_noninteractive_and_exports_only_live_paths);
TEST_MAIN_END()
