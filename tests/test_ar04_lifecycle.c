/* AR-04 account lifecycle regressions: active-edit refusal, remove teardown,
 * and exact current-account detection for names containing ".sock". */

#include "test.h"
#include "accounts.h"
#include "error.h"
#include "gitswitch.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
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

static int install_live_current_socket(const char *runtime,
                                       const char *account_name);

static int resolve_binary(void) {
    const char *bin = getenv("GITSWITCH_BIN");

    if (!bin || !*bin) bin = "build/bin/gitswitch";
    if (!realpath(bin, g_bin) || access(g_bin, X_OK) != 0) {
        fprintf(stderr, "test_ar04_lifecycle: executable not found at %s\n", bin);
        return -1;
    }
    return 0;
}

static int make_temp_dir(char *buf, size_t size) {
    if (snprintf(buf, size, "/tmp/gitswitch-ar04-life-XXXXXX") < 0 ||
        !ts_mkdtemp(buf)) {
        return -1;
    }
    return 0;
}

static void remove_tree(const char *path) {
    char cmd[2048];
    int status;

    if (!path || !*path || strchr(path, '\'')) return;
    if (snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path) < 0) return;
    status = system(cmd);
    (void)status;
}

static int mkdir_private(const char *path) {
    if (mkdir(path, 0700) != 0 && errno != EEXIST) return -1;
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

static int write_text(const char *path, const char *text, mode_t mode) {
    FILE *f = fopen(path, "w");

    if (!f) return -1;
    if (fputs(text, f) == EOF || fclose(f) != 0) return -1;
    return chmod(path, mode);
}

static const char *slurp(const char *path, char *buf, size_t size) {
    FILE *f;
    size_t n;

    buf[0] = '\0';
    f = fopen(path, "r");
    if (!f) return buf;
    n = fread(buf, 1, size - 1, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

/* AR-06 F33: -(1000+signal) for a crash/signal-kill, -1 for a system()
 * failure, so abnormal termination never passes as an ordinary nonzero exit. */
static int run_shell(const char *cmd) {
    int status = system(cmd);

    if (status == -1) return -1;
    if (!WIFEXITED(status))
        return WIFSIGNALED(status) ? -(1000 + WTERMSIG(status)) : -1;
    return WEXITSTATUS(status);
}

static int prepare_home(const char *home, const char *config_body) {
    char path[1024];

    snprintf(path, sizeof(path), "%s/.config", home);
    if (mkdir_private(path) != 0) return -1;
    snprintf(path, sizeof(path), "%s/.config/gitswitch", home);
    if (mkdir_private(path) != 0) return -1;
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    if (write_text(path, config_body, 0600) != 0) return -1;

    /* Historical active-only files predate the consolidated artifact. Remove
     * state left by an earlier command in this reused HOME so this fixture
     * exercises migration from settings.active_account itself. */
    snprintf(path, sizeof(path), "%s/.config/gitswitch/.resume-hint", home);
    return unlink(path) == 0 || errno == ENOENT ? 0 : -1;
}

static const char *active_work_config(void) {
    return "[settings]\n"
           "default_scope = \"global\"\n"
           "active_account = \"work\"\n"
           "\n"
           "[accounts.1]\n"
           "name = \"work\"\n"
           "email = \"old@example.com\"\n"
           "description = \"old description\"\n"
           "preferred_scope = \"global\"\n";
}

static int prepare_shims(char *shim_dir, size_t size) {
    char path[1024];

    if (!ts_mkdtemp_trusted(shim_dir, size,
                            "gitswitch-ar04-life-shims")) return -1;
    snprintf(path, sizeof(path), "%s/gpg", shim_dir);
    if (write_text(path, "#!/bin/sh\nexit 0\n", 0700) != 0) return -1;
    snprintf(path, sizeof(path), "%s/gpgconf", shim_dir);
    return write_text(path, "#!/bin/sh\nexit 0\n", 0700);
}

static int run_edit(const char *home, const char *runtime, const char *shim_dir,
                    const char *input, const char *output) {
    char stdin_path[1024];
    char cmd[8192];

    snprintf(stdin_path, sizeof(stdin_path), "%s/edit.in", runtime);
    if (write_text(stdin_path, input, 0600) != 0) return -1;
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' PATH='%s:/usr/bin:/bin' "
             "'%s' -C -y edit work <'%s' >'%s' 2>&1",
             home, runtime, shim_dir, g_bin, stdin_path, output);
    return run_shell(cmd);
}

TEST(active_live_field_edits_are_rejected_without_mutation) {
    char home[256], runtime[256], shims[512], key[1024];
    char config_path[1024], git_path[1024], output[1024];
    char before_config[8192], before_git[8192], after[8192], out[8192];
    char ssh_input[2048];
    const char *inputs[6];
    size_t i;

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_shims(shims, sizeof(shims)), 0);
    snprintf(key, sizeof(key), "%s/new-key", runtime);
    CHECK_EQ_INT(write_text(key,
                            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                            "test\n-----END OPENSSH PRIVATE KEY-----\n",
                            0600), 0);
    snprintf(ssh_input, sizeof(ssh_input), "\n\n\n%s\n\n\n\n", key);
    inputs[0] = "renamed\n\n\n\n\n\n";
    inputs[1] = "\nnew@example.com\n\n\n\n\n";
    inputs[2] = "renamed\nnew@example.com\n\n\n\nlocal\n";
    inputs[3] = "\n\n\n\n\nlocal\n";
    inputs[4] = ssh_input;
    inputs[5] = "\n\n\n\nABCDEF0123456789\n\n\n";

    snprintf(config_path, sizeof(config_path),
             "%s/.config/gitswitch/accounts.toml", home);
    snprintf(git_path, sizeof(git_path), "%s/.gitconfig", home);
    snprintf(output, sizeof(output), "%s/edit.out", runtime);

    for (i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        CHECK_EQ_INT(prepare_home(home, active_work_config()), 0);
        CHECK_EQ_INT(write_text(git_path,
                                "[user]\n\tname = work\n\temail = old@example.com\n",
                                0600), 0);
        slurp(config_path, before_config, sizeof(before_config));
        slurp(git_path, before_git, sizeof(before_git));
        CHECK(run_edit(home, runtime, shims, inputs[i], output) != 0);
        slurp(config_path, after, sizeof(after));
        CHECK_STR_EQ(after, before_config);
        slurp(git_path, after, sizeof(after));
        CHECK_STR_EQ(after, before_git);
        slurp(output, out, sizeof(out));
        CHECK(strstr(out, "Cannot change live fields for active account 'work'") != NULL);
        CHECK(strstr(out, "switch away or reset it, then rerun edit") != NULL);
    }

    remove_tree(home);
    remove_tree(runtime);
}

TEST(active_description_edit_and_inactive_live_edits_still_work) {
    char home[256], runtime[256], shims[512], output[1024], path[1024];
    char key[1024], input[2048], contents[16384], before_git[4096];
    char ssh_target[1024], ssh_current[1024], gpg_target[1024], gpg_current[1024];
    char link_target[1024];
    struct stat ssh_before, ssh_after, gpg_before, gpg_after;
    ssize_t link_len;
    int listener = -1;
    static const char inactive_config[] =
        "[settings]\n"
        "default_scope = \"global\"\n"
        "active_account = \"other\"\n"
        "\n"
        "[accounts.1]\n"
        "name = \"work\"\n"
        "email = \"old@example.com\"\n"
        "description = \"old description\"\n"
        "preferred_scope = \"global\"\n"
        "\n"
        "[accounts.2]\n"
        "name = \"other\"\n"
        "email = \"other@example.com\"\n"
        "preferred_scope = \"global\"\n";
    static const char cleared_active_config[] =
        "[settings]\n"
        "default_scope = \"global\"\n"
        "active_account = \"\"\n"
        "\n"
        "[accounts.1]\n"
        "name = \"work\"\n"
        "email = \"old@example.com\"\n"
        "description = \"old description\"\n"
        "preferred_scope = \"global\"\n";

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_shims(shims, sizeof(shims)), 0);
    snprintf(output, sizeof(output), "%s/edit.out", runtime);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);

    CHECK_EQ_INT(prepare_home(home, active_work_config()), 0);
    snprintf(path, sizeof(path), "%s/.gitconfig", home);
    CHECK_EQ_INT(write_text(path,
                            "[user]\n\tname = work\n\temail = old@example.com\n",
                            0600), 0);
    slurp(path, before_git, sizeof(before_git));

    snprintf(ssh_target, sizeof(ssh_target),
             "%s/gitswitch-ssh/ssh-agent.work.sock", runtime);
    snprintf(ssh_current, sizeof(ssh_current),
             "%s/gitswitch-ssh/current.sock", runtime);
    listener = install_live_current_socket(runtime, "work");
    CHECK(listener >= 0);
    CHECK_EQ_INT(lstat(ssh_current, &ssh_before), 0);

    snprintf(path, sizeof(path), "%s/gitswitch-gpg", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(gpg_target, sizeof(gpg_target), "%s/gitswitch-gpg/work", runtime);
    CHECK_EQ_INT(mkdir_private(gpg_target), 0);
    snprintf(gpg_current, sizeof(gpg_current), "%s/gitswitch-gpg/current", runtime);
    CHECK_EQ_INT(symlink(gpg_target, gpg_current), 0);
    CHECK_EQ_INT(lstat(gpg_current, &gpg_before), 0);

    CHECK_EQ_INT(run_edit(home, runtime, shims,
                          "\n\nmetadata only\n\n\n\n", output), 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "description = \"metadata only\"") != NULL);
    CHECK(strstr(contents, "email = \"old@example.com\"") != NULL);
    snprintf(path, sizeof(path), "%s/.gitconfig", home);
    slurp(path, contents, sizeof(contents));
    CHECK_STR_EQ(contents, before_git);
    CHECK_EQ_INT(lstat(ssh_current, &ssh_after), 0);
    CHECK_EQ_INT(lstat(gpg_current, &gpg_after), 0);
    CHECK(ssh_before.st_dev == ssh_after.st_dev &&
          ssh_before.st_ino == ssh_after.st_ino);
    CHECK(gpg_before.st_dev == gpg_after.st_dev &&
          gpg_before.st_ino == gpg_after.st_ino);
    link_len = readlink(ssh_current, link_target, sizeof(link_target) - 1);
    CHECK(link_len > 0);
    if (link_len > 0) {
        link_target[link_len] = '\0';
        CHECK_STR_EQ(link_target, ssh_target);
    }
    link_len = readlink(gpg_current, link_target, sizeof(link_target) - 1);
    CHECK(link_len > 0);
    if (link_len > 0) {
        link_target[link_len] = '\0';
        CHECK_STR_EQ(link_target, gpg_target);
    }

    /* The remainder of this test exercises edits to an inactive `work`
     * account. Remove the deliberately-live `work` runtime first so startup
     * detection does not correctly classify it as active. */
    if (listener >= 0) {
        close(listener);
        listener = -1;
    }
    CHECK_EQ_INT(unlink(ssh_current), 0);
    CHECK_EQ_INT(unlink(ssh_target), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-ssh/.lock", runtime);
    CHECK(unlink(path) == 0 || errno == ENOENT);
    snprintf(path, sizeof(path), "%s/gitswitch-ssh", runtime);
    CHECK_EQ_INT(rmdir(path), 0);
    CHECK_EQ_INT(unlink(gpg_current), 0);
    CHECK_EQ_INT(rmdir(gpg_target), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/.lock", runtime);
    CHECK(unlink(path) == 0 || errno == ENOENT);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg", runtime);
    CHECK_EQ_INT(rmdir(path), 0);

    /* The documented recovery workflow is not merely "make some other account
     * active": after clearing active_account entirely, the exact email change
     * rejected above must be accepted and persisted. */
    CHECK_EQ_INT(prepare_home(home, cleared_active_config), 0);
    CHECK_EQ_INT(run_edit(home, runtime, shims,
                          "\nnew@example.com\n\n\n\n\n", output), 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    /* Saving canonicalizes a cleared marker by omitting the empty setting; an
     * explicit empty value is equally valid, but no nonempty marker may return. */
    CHECK(strstr(contents, "active_account =") == NULL ||
          strstr(contents, "active_account = \"\"") != NULL);
    CHECK(strstr(contents, "name = \"work\"") != NULL);
    CHECK(strstr(contents, "email = \"new@example.com\"") != NULL);

    CHECK_EQ_INT(prepare_home(home, inactive_config), 0);
    CHECK_EQ_INT(run_edit(home, runtime, shims,
                          "renamed\nnew@example.com\n\n\n\n\n", output), 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "name = \"renamed\"") != NULL);
    CHECK(strstr(contents, "email = \"new@example.com\"") != NULL);
    CHECK(strstr(contents, "active_account") == NULL);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/.resume-hint", home);
    slurp(path, contents, sizeof(contents));
    CHECK_STR_EQ(contents, "none\nactive=other\n");

    CHECK_EQ_INT(prepare_home(home, inactive_config), 0);
    snprintf(key, sizeof(key), "%s/inactive-key", runtime);
    CHECK_EQ_INT(write_text(key,
                            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                            "test\n-----END OPENSSH PRIVATE KEY-----\n",
                            0600), 0);
    snprintf(input, sizeof(input),
             "\n\n\n%s\ngithub.com-work\nABCDEF0123456789\ny\n\n", key);
    CHECK_EQ_INT(run_edit(home, runtime, shims, input, output), 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "ssh_key = ") != NULL);
    CHECK(strstr(contents, "ssh_host = \"github.com-work\"") != NULL);
    CHECK(strstr(contents, "gpg_key = \"ABCDEF0123456789\"") != NULL);

    remove_tree(home);
    remove_tree(runtime);
}

static int run_remove(const char *home, const char *runtime,
                      const char *shim_dir, const char *account,
                      const char *output) {
    char cmd[8192];

    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' PATH='%s:/usr/bin:/bin' "
             "'%s' -C -y remove '%s' </dev/null >'%s' 2>&1",
             home, runtime, shim_dir, g_bin, account, output);
    return run_shell(cmd);
}

TEST(remove_tears_down_runtime_before_deleting_account) {
    char home[256], runtime[256], shims[512], path[1024], target[1024];
    char output[1024], contents[8192], cmd[4096], pid_text[64];
    pid_t agent_pid = -1;
    bool real_agent = false;

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_shims(shims, sizeof(shims)), 0);
    CHECK_EQ_INT(prepare_home(home, active_work_config()), 0);

    snprintf(path, sizeof(path), "%s/gitswitch-ssh", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(target, sizeof(target), "%s/gitswitch-ssh/ssh-agent.work.sock", runtime);
    if (run_shell("command -v ssh-agent >/dev/null 2>&1") == 0) {
        char *pid_marker;

        snprintf(output, sizeof(output), "%s/ssh-agent.out", runtime);
        snprintf(cmd, sizeof(cmd),
                 "PATH='/usr/bin:/bin:/usr/local/bin' ssh-agent -s -a '%s' "
                 ">'%s' 2>/dev/null",
                 target, output);
        CHECK_EQ_INT(run_shell(cmd), 0);
        slurp(output, contents, sizeof(contents));
        pid_marker = strstr(contents, "SSH_AGENT_PID=");
        CHECK(pid_marker != NULL);
        if (pid_marker) {
            agent_pid = (pid_t)strtol(pid_marker + strlen("SSH_AGENT_PID="),
                                      NULL, 10);
        }
        CHECK(agent_pid > 1);
        if (agent_pid > 1) {
            snprintf(path, sizeof(path),
                     "%s/gitswitch-ssh/ssh-agent.work.pid", runtime);
            snprintf(pid_text, sizeof(pid_text), "%ld\n", (long)agent_pid);
            CHECK_EQ_INT(write_text(path, pid_text, 0600), 0);
            real_agent = true;
        }
    } else {
        fprintf(stderr, "  (skipped real-agent assertion: ssh-agent not installed)\n");
        CHECK_EQ_INT(write_text(target, "socket fixture\n", 0600), 0);
    }
    snprintf(path, sizeof(path), "%s/gitswitch-ssh/current.sock", runtime);
    CHECK_EQ_INT(symlink(target, path), 0);

    snprintf(path, sizeof(path), "%s/gitswitch-gpg", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(target, sizeof(target), "%s/gitswitch-gpg/work", runtime);
    CHECK_EQ_INT(mkdir_private(target), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/current", runtime);
    CHECK_EQ_INT(symlink(target, path), 0);

    snprintf(output, sizeof(output), "%s/remove.out", runtime);
    CHECK_EQ_INT(run_remove(home, runtime, shims, "work", output), 0);
    if (real_agent) {
        errno = 0;
        CHECK(kill(agent_pid, 0) != 0);
        CHECK_EQ_INT(errno, ESRCH);
        snprintf(path, sizeof(path),
                 "%s/gitswitch-ssh/ssh-agent.work.pid", runtime);
        CHECK(access(path, F_OK) != 0);
    }
    snprintf(path, sizeof(path), "%s/gitswitch-ssh/ssh-agent.work.sock", runtime);
    CHECK(access(path, F_OK) != 0);
    snprintf(path, sizeof(path), "%s/gitswitch-ssh/current.sock", runtime);
    CHECK(access(path, F_OK) != 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/work", runtime);
    CHECK(access(path, F_OK) != 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/current", runtime);
    CHECK(access(path, F_OK) != 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "name = \"work\"") == NULL);
    CHECK(strstr(contents, "active_account = \"work\"") == NULL);

    if (agent_pid > 1 && kill(agent_pid, 0) == 0) {
        (void)kill(agent_pid, SIGKILL);
    }

    remove_tree(home);
    remove_tree(runtime);
}

TEST(remove_save_failure_keeps_retry_handle_after_runtime_teardown) {
    char home[256], runtime[256], shims[512], config_dir[1024];
    char path[1024], target[1024], output[1024], cmd[8192], contents[8192];
    char key_path[1024], config_body[4096], current_path[1024];
    char socket_path[1024], pid_path[1024], link_target[1024];
    struct stat st;
    ssize_t link_len;
    pid_t retry_pid = -1;
    FILE *lock_file;

    if (getuid() == 0) {
        fprintf(stderr, "  (skipped: root bypasses the save permission fixture)\n");
        return;
    }

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_shims(shims, sizeof(shims)), 0);
    CHECK_EQ_INT(join_path(key_path, sizeof(key_path), runtime, "/retry-key"), 0);
    snprintf(cmd, sizeof(cmd),
             "PATH='/usr/bin:/bin:/usr/local/bin' ssh-keygen -q -t ed25519 "
             "-N '' -f '%s' >/dev/null 2>&1",
             key_path);
    CHECK_EQ_INT(run_shell(cmd), 0);
    snprintf(config_body, sizeof(config_body),
             "[settings]\n"
             "default_scope = \"global\"\n"
             "active_account = \"work\"\n"
             "\n"
             "[accounts.1]\n"
             "name = \"work\"\n"
             "email = \"old@example.com\"\n"
             "description = \"old description\"\n"
             "preferred_scope = \"global\"\n"
             "ssh_key = \"%s\"\n",
             key_path);
    CHECK_EQ_INT(prepare_home(home, config_body), 0);

    /* Give teardown a real owned GPG home to remove before persistence is
     * forced to fail. The on-disk account must remain as the retry handle. */
    snprintf(path, sizeof(path), "%s/gitswitch-gpg", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(target, sizeof(target), "%s/gitswitch-gpg/work", runtime);
    CHECK_EQ_INT(mkdir_private(target), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/current", runtime);
    CHECK_EQ_INT(symlink(target, path), 0);

    snprintf(config_dir, sizeof(config_dir), "%s/.config/gitswitch", home);
    CHECK_EQ_INT(join_path(path, sizeof(path), config_dir, "/.config.lock"), 0);
    lock_file = fopen(path, "w");
    CHECK(lock_file != NULL);
    if (lock_file) fclose(lock_file);
    CHECK_EQ_INT(chmod(path, 0600), 0);
    CHECK_EQ_INT(chmod(config_dir, 0500), 0);

    snprintf(output, sizeof(output), "%s/remove-save-failure.out", runtime);
    CHECK(run_remove(home, runtime, shims, "work", output) != 0);
    slurp(output, contents, sizeof(contents));
    CHECK(strstr(contents, "Failed to save configuration changes") != NULL);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/work", runtime);
    CHECK(access(path, F_OK) != 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "name = \"work\"") != NULL);
    CHECK(strstr(contents, "active_account = \"work\"") != NULL);

    /* Reload by switching again after the persistence fault is removed. This
     * proves the retained account is not merely listable: its SSH runtime can
     * be recreated cleanly after the earlier teardown. */
    CHECK_EQ_INT(chmod(config_dir, 0700), 0);
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' XDG_RUNTIME_DIR='%s' "
             "PATH='%s:/usr/local/bin:/usr/bin:/bin' "
             "'%s' -C -y work >'%s' 2>&1",
             home, runtime, shims, g_bin, output);
    int switch_rc = run_shell(cmd);
    slurp(output, contents, sizeof(contents));
    if (switch_rc != 0) {
        fprintf(stderr, "  retry switch output:\n%s\n", contents);
    }
    CHECK_EQ_INT(switch_rc, 0);
    CHECK(strstr(contents, "SSH key loaded") != NULL);

    CHECK_EQ_INT(join_path(socket_path, sizeof(socket_path), runtime,
                           "/gitswitch-ssh/ssh-agent.work.sock"), 0);
    CHECK_EQ_INT(join_path(current_path, sizeof(current_path), runtime,
                           "/gitswitch-ssh/current.sock"), 0);
    CHECK_EQ_INT(join_path(pid_path, sizeof(pid_path), runtime,
                           "/gitswitch-ssh/ssh-agent.work.pid"), 0);
    CHECK_EQ_INT(lstat(current_path, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
    link_len = readlink(current_path, link_target, sizeof(link_target) - 1);
    CHECK(link_len > 0);
    if (link_len > 0) {
        link_target[link_len] = '\0';
        CHECK_STR_EQ(link_target, socket_path);
    }
    CHECK_EQ_INT(stat(current_path, &st), 0);
    CHECK(S_ISSOCK(st.st_mode));
    slurp(pid_path, contents, sizeof(contents));
    retry_pid = (pid_t)strtol(contents, NULL, 10);
    CHECK(retry_pid > 1);

    CHECK_EQ_INT(run_remove(home, runtime, shims, "work", output), 0);
    if (retry_pid > 1) {
        errno = 0;
        CHECK(kill(retry_pid, 0) != 0);
        CHECK_EQ_INT(errno, ESRCH);
    }
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "name = \"work\"") == NULL);

    if (retry_pid > 1 && kill(retry_pid, 0) == 0) {
        (void)kill(retry_pid, SIGKILL);
    }

    remove_tree(home);
    remove_tree(runtime);
}

TEST(remove_failure_retains_account_and_attempts_other_manager) {
    char home[256], runtime[256], shims[512], path[1024], target[1024];
    char output[1024], contents[8192];
    struct stat link_st;

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_shims(shims, sizeof(shims)), 0);
    CHECK_EQ_INT(prepare_home(home, active_work_config()), 0);
    snprintf(target, sizeof(target), "%s/foreign-ssh", runtime);
    CHECK_EQ_INT(mkdir_private(target), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-ssh", runtime);
    CHECK_EQ_INT(symlink(target, path), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/current", runtime);
    CHECK_EQ_INT(symlink("missing", path), 0);
    CHECK_EQ_INT(lstat(path, &link_st), 0);
    CHECK(S_ISLNK(link_st.st_mode));

    snprintf(output, sizeof(output), "%s/remove.out", runtime);
    CHECK(run_remove(home, runtime, shims, "work", output) != 0);
    /* GPG reset still attempted: gpg_manager_reset unlinks the dangling
     * `current` link, so the LINK must be gone. access() follows symlinks
     * and returned -1 either way — a tautological witness (AR-05 M6). */
    errno = 0;
    CHECK(lstat(path, &link_st) != 0 && errno == ENOENT);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "name = \"work\"") != NULL);
    CHECK(strstr(contents, "active_account = \"work\"") != NULL);
    slurp(output, contents, sizeof(contents));
    CHECK(strstr(contents, "account retained for retry") != NULL);

    /* The inverse partial failure: SSH cleanup succeeds, GPG lock fails, and
     * the account remains so the next remove/reset can retry. */
    remove_tree(runtime);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_shims(shims, sizeof(shims)), 0);
    CHECK_EQ_INT(prepare_home(home, active_work_config()), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-ssh", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(target, sizeof(target), "%s/gitswitch-ssh/ssh-agent.work.sock", runtime);
    CHECK_EQ_INT(write_text(target, "socket fixture\n", 0600), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/.lock", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(output, sizeof(output), "%s/remove.out", runtime);
    CHECK(run_remove(home, runtime, shims, "work", output) != 0);
    snprintf(path, sizeof(path), "%s/gitswitch-ssh/ssh-agent.work.sock", runtime);
    CHECK(access(path, F_OK) != 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "name = \"work\"") != NULL);
    CHECK(strstr(contents, "active_account = \"work\"") != NULL);

    remove_tree(home);
    remove_tree(runtime);
}

TEST(remove_inactive_account_with_no_runtime_preserves_active_account) {
    char home[256], runtime[256], shims[512], output[1024], path[1024];
    char contents[8192], ssh_target[1024], ssh_current[1024];
    char gpg_target[1024], gpg_current[1024], link_target[1024];
    ssize_t link_len;
    static const char body[] =
        "[settings]\n"
        "default_scope = \"global\"\n"
        "active_account = \"other\"\n"
        "\n"
        "[accounts.1]\n"
        "name = \"work\"\n"
        "email = \"work@example.com\"\n"
        "preferred_scope = \"global\"\n"
        "\n"
        "[accounts.2]\n"
        "name = \"other\"\n"
        "email = \"other@example.com\"\n"
        "preferred_scope = \"global\"\n";

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_shims(shims, sizeof(shims)), 0);
    CHECK_EQ_INT(prepare_home(home, body), 0);

    /* Give the active account real stable entry points. Removing the inactive
     * account must not tear either one down. */
    snprintf(path, sizeof(path), "%s/gitswitch-ssh", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(ssh_target, sizeof(ssh_target),
             "%s/gitswitch-ssh/ssh-agent.other.sock", runtime);
    CHECK_EQ_INT(write_text(ssh_target, "active ssh runtime\n", 0600), 0);
    snprintf(ssh_current, sizeof(ssh_current),
             "%s/gitswitch-ssh/current.sock", runtime);
    CHECK_EQ_INT(symlink(ssh_target, ssh_current), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(gpg_target, sizeof(gpg_target), "%s/gitswitch-gpg/other", runtime);
    CHECK_EQ_INT(mkdir_private(gpg_target), 0);
    snprintf(gpg_current, sizeof(gpg_current), "%s/gitswitch-gpg/current", runtime);
    CHECK_EQ_INT(symlink(gpg_target, gpg_current), 0);

    snprintf(output, sizeof(output), "%s/remove.out", runtime);
    CHECK_EQ_INT(run_remove(home, runtime, shims, "work", output), 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "name = \"work\"") == NULL);
    CHECK(strstr(contents, "active_account") == NULL);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/.resume-hint", home);
    slurp(path, contents, sizeof(contents));
    CHECK_STR_EQ(contents, "none\nactive=other\n");
    link_len = readlink(ssh_current, link_target, sizeof(link_target) - 1);
    CHECK(link_len > 0);
    if (link_len > 0) {
        link_target[link_len] = '\0';
        CHECK_STR_EQ(link_target, ssh_target);
    }
    CHECK(access(ssh_target, F_OK) == 0);
    link_len = readlink(gpg_current, link_target, sizeof(link_target) - 1);
    CHECK(link_len > 0);
    if (link_len > 0) {
        link_target[link_len] = '\0';
        CHECK_STR_EQ(link_target, gpg_target);
    }
    CHECK(access(gpg_target, F_OK) == 0);

    remove_tree(home);
    remove_tree(runtime);
}

TEST(remove_rebinds_current_pointer_after_array_compaction) {
    gitswitch_ctx_t ctx;
    char runtime[256];

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);

    ctx.account_count = 3;
    ctx.config.assume_yes = true;
    ctx.accounts[0].id = 1;
    snprintf(ctx.accounts[0].name, sizeof(ctx.accounts[0].name), "remove-me");
    ctx.accounts[1].id = 2;
    snprintf(ctx.accounts[1].name, sizeof(ctx.accounts[1].name), "current");
    ctx.accounts[2].id = 3;
    snprintf(ctx.accounts[2].name, sizeof(ctx.accounts[2].name), "later");
    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account), "current");
    ctx.current_account = &ctx.accounts[1];

    CHECK_EQ_INT(accounts_remove(&ctx, "remove-me"), 0);
    CHECK_EQ_INT((int)ctx.account_count, 2);
    CHECK(ctx.current_account == &ctx.accounts[0]);
    CHECK_STR_EQ(ctx.current_account->name, "current");
    CHECK_STR_EQ(ctx.config.active_account, "current");

    unsetenv("XDG_RUNTIME_DIR");
    remove_tree(runtime);
}

static void add_account(gitswitch_ctx_t *ctx, size_t index, const char *name) {
    account_t *account = &ctx->accounts[index];

    memset(account, 0, sizeof(*account));
    account->id = (uint32_t)index + 1;
    snprintf(account->name, sizeof(account->name), "%s", name);
    snprintf(account->email, sizeof(account->email), "%s@example.com", name);
    ctx->account_count = index + 1;
}

static int install_current_link(const char *runtime, const char *target) {
    char path[1024];

    snprintf(path, sizeof(path), "%s/gitswitch-ssh", runtime);
    if (mkdir_private(path) != 0) return -1;
    snprintf(path, sizeof(path), "%s/gitswitch-ssh/current.sock", runtime);
    unlink(path);
    return symlink(target, path);
}

static int install_live_current_socket(const char *runtime,
                                       const char *account_name) {
    char dir[1024];
    char current[1024];
    char socket_path[1024];
    struct sockaddr_un addr;
    int fd;

    if ((size_t)snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", runtime) >=
        sizeof(dir)) {
        return -1;
    }
    if (mkdir_private(dir) != 0) return -1;
    if ((size_t)snprintf(socket_path, sizeof(socket_path),
                         "%s/ssh-agent.%s.sock", dir, account_name) >=
        sizeof(socket_path)) {
        return -1;
    }
    if (strlen(socket_path) >= sizeof(addr.sun_path)) return -1;

    unlink(socket_path);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, socket_path, strlen(socket_path) + 1);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        chmod(socket_path, 0600) != 0 || listen(fd, 4) != 0) {
        close(fd);
        unlink(socket_path);
        return -1;
    }

    if ((size_t)snprintf(current, sizeof(current), "%s/current.sock", dir) >=
        sizeof(current)) {
        close(fd);
        unlink(socket_path);
        return -1;
    }
    unlink(current);
    if (symlink(socket_path, current) != 0) {
        close(fd);
        unlink(socket_path);
        return -1;
    }
    return fd;
}

TEST(sock_substrings_round_trip_and_malformed_links_fall_back) {
    char runtime[256];
    gitswitch_ctx_t ctx;
    int listener;

    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);
    memset(&ctx, 0, sizeof(ctx));
    add_account(&ctx, 0, "alice.sock.work");
    add_account(&ctx, 1, "a.sock.b.sock.c");
    add_account(&ctx, 2, "saved");
    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account), "%s", "saved");

    listener = install_live_current_socket(runtime, "alice.sock.work");
    CHECK(listener >= 0);
    CHECK_EQ_INT(accounts_detect_current(&ctx), 0);
    CHECK(ctx.current_account == &ctx.accounts[0]);
    if (listener >= 0) close(listener);

    ctx.current_account = NULL;
    listener = install_live_current_socket(runtime, "a.sock.b.sock.c");
    CHECK(listener >= 0);
    CHECK_EQ_INT(accounts_detect_current(&ctx), 0);
    CHECK(ctx.current_account == &ctx.accounts[1]);
    if (listener >= 0) close(listener);

    ctx.current_account = NULL;
    CHECK_EQ_INT(install_current_link(runtime,
                 "/tmp/ssh-agent.alice.sock.work.sock.extra"), 0);
    CHECK_EQ_INT(accounts_detect_current(&ctx), 0);
    CHECK(ctx.current_account == &ctx.accounts[2]);

    ctx.current_account = NULL;
    CHECK_EQ_INT(install_current_link(runtime,
                 "/tmp/ssh-agent.deleted.sock"), 0);
    CHECK_EQ_INT(accounts_detect_current(&ctx), 0);
    CHECK(ctx.current_account == &ctx.accounts[2]);

    ctx.current_account = NULL;
    {
        char path[1024];
        snprintf(path, sizeof(path), "%s/gitswitch-ssh/current.sock", runtime);
        unlink(path);
    }
    CHECK_EQ_INT(accounts_detect_current(&ctx), 0);
    CHECK(ctx.current_account == &ctx.accounts[2]);

    remove_tree(runtime);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    if (resolve_binary() != 0) return 1;
    RUN_TEST(active_live_field_edits_are_rejected_without_mutation);
    RUN_TEST(active_description_edit_and_inactive_live_edits_still_work);
    RUN_TEST(remove_tears_down_runtime_before_deleting_account);
    RUN_TEST(remove_save_failure_keeps_retry_handle_after_runtime_teardown);
    RUN_TEST(remove_failure_retains_account_and_attempts_other_manager);
    RUN_TEST(remove_inactive_account_with_no_runtime_preserves_active_account);
    RUN_TEST(remove_rebinds_current_pointer_after_array_compaction);
    RUN_TEST(sock_substrings_round_trip_and_malformed_links_fall_back);
TEST_MAIN_END()
