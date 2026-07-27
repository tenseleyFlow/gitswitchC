/* AR-07 T13: executable ancestry/descriptor trust and absolute runtime roots. */
#include "test.h"
#include "gitswitch.h"
#include "utils.h"
#include "error.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char g_self_path[MAX_PATH_LEN];
static char g_swap_expected[MAX_PATH_LEN];
static char g_swap_backup[MAX_PATH_LEN];
static char g_swap_target[MAX_PATH_LEN];
static int g_hook_result;

static bool make_safe_fixture(char *root, size_t root_size,
                              char *bin, size_t bin_size) {
    char tmpl[MAX_PATH_LEN];

    if (!ts_mkdtemp_trusted(tmpl, sizeof(tmpl), "gitswitch-ar07-exec") ||
        (size_t)snprintf(root, root_size, "%s", tmpl) >= root_size ||
        (size_t)snprintf(bin, bin_size, "%s/bin", tmpl) >= bin_size ||
        mkdir(bin, 0700) != 0) {
        return false;
    }
    return true;
}

static bool install_self_copy(const char *path, mode_t mode) {
    return copy_file(g_self_path, path) == 0 && chmod(path, mode) == 0;
}

static bool write_fixture_bytes(const char *path, const void *bytes,
                                size_t size, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return false;

    const unsigned char *cursor = bytes;
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t written = write(fd, cursor, remaining);
        if (written > 0) {
            cursor += (size_t)written;
            remaining -= (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            int saved_errno = written < 0 ? errno : EIO;
            close(fd);
            errno = saved_errno;
            return false;
        }
    }
    if (fchmod(fd, mode) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return false;
    }
    return close(fd) == 0;
}

static void save_environment(const char *name, char **saved, bool *had) {
    const char *value = getenv(name);
    *had = value != NULL;
    *saved = value ? strdup(value) : NULL;
}

static void restore_environment(const char *name, char *saved, bool had) {
    if (had) {
        CHECK(saved != NULL);
        if (saved) CHECK_EQ_INT(setenv(name, saved, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv(name), 0);
    }
    free(saved);
}

static void check_probe_and_runner_reject(const char *command) {
    char resolved[MAX_PATH_LEN];
    const char *argv[] = {command, NULL};
    run_result_t result;

    CHECK_EQ_INT(find_command_path(command, resolved, sizeof(resolved)), -1);
    CHECK(!command_exists(command));
    clear_error();
    CHECK_EQ_INT(run_argv(argv, NULL, &result), -1);
    CHECK(!result.spawned);
}

static void check_probe_and_runner_accept(const char *command,
                                          const char *argument) {
    char resolved[MAX_PATH_LEN];
    const char *argv[] = {command, argument, NULL};
    run_result_t result;

    CHECK_EQ_INT(find_command_path(command, resolved, sizeof(resolved)), 0);
    CHECK(resolved[0] == '/');
    CHECK(command_exists(command));
    clear_error();
    CHECK_EQ_INT(run_argv(argv, NULL, &result), 0);
    CHECK(result.spawned);
    CHECK_EQ_INT(result.exit_code, 0);
}

static void replace_after_pin(const char *resolved_path) {
    g_hook_result = -1;
    if (strcmp(resolved_path, g_swap_expected) != 0) return;
    if (rename(resolved_path, g_swap_backup) != 0) return;
    if (symlink(g_swap_target, resolved_path) != 0) {
        (void)rename(g_swap_backup, resolved_path);
        return;
    }
    g_hook_result = 0;
}

static void replace_interpreter_after_pin(const char *resolved_path) {
    (void)resolved_path;
    g_hook_result = -1;
    if (rename(g_swap_expected, g_swap_backup) != 0) return;
    if (symlink(g_swap_target, g_swap_expected) != 0) {
        (void)rename(g_swap_backup, g_swap_expected);
        return;
    }
    g_hook_result = 0;
}

static void make_pinned_file_group_writable(const char *resolved_path) {
    g_hook_result = strcmp(resolved_path, g_swap_expected) == 0 &&
                            chmod(resolved_path, 0775) == 0
                        ? 0
                        : -1;
}

static bool reap_within(pid_t pid, int timeout_ms, int *status_out) {
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000L};
    int elapsed = 0;
    while (elapsed <= timeout_ms) {
        int status = 0;
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            if (status_out) *status_out = status;
            return true;
        }
        if (waited < 0 && errno != EINTR) return false;
        nanosleep(&pause, NULL);
        elapsed += 10;
    }
    kill(pid, SIGKILL);
    (void)waitpid(pid, NULL, 0);
    return false;
}

TEST(long_trusted_home_fixtures_are_tracked_without_path_cap) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN];
    char long_home[MAX_PATH_LEN], created[MAX_PATH_LEN];
    char original_home[MAX_PATH_LEN];
    char component[121];
    const char *home = getenv("HOME");

    CHECK(home != NULL);
    if (!home || safe_strncpy(original_home, home,
                              sizeof(original_home)) != 0) {
        return;
    }
    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin))) {
        CHECK(!"long HOME fixture root creation failed");
        return;
    }
    memset(component, 'h', sizeof(component) - 1);
    component[sizeof(component) - 1] = '\0';
    CHECK((size_t)snprintf(long_home, sizeof(long_home), "%s/%s",
                           root, component) < sizeof(long_home));
    CHECK_EQ_INT(mkdir(long_home, 0700), 0);
    CHECK_EQ_INT(setenv("HOME", long_home, 1), 0);

    char *fixture = ts_mkdtemp_trusted(created, sizeof(created),
                                       "ar07-long-home");
    CHECK(fixture != NULL);
    if (fixture) CHECK(strlen(fixture) >= 96);

    CHECK_EQ_INT(setenv("HOME", original_home, 1), 0);
}

#if defined(__APPLE__) || defined(__FreeBSD__)
static int change_extended_acl(const char *path, bool clear) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
#if defined(__APPLE__)
        if (clear) {
            execl("/bin/chmod", "chmod", "-N", path, (char *)NULL);
        } else {
            execl("/bin/chmod", "chmod", "+a", "everyone allow write",
                  path, (char *)NULL);
        }
#else
        if (clear) {
            execl("/bin/setfacl", "setfacl", "-b", path, (char *)NULL);
        } else {
            execl("/bin/setfacl", "setfacl", "-m", "u:nobody:r-x",
                  path, (char *)NULL);
        }
#endif
        _exit(127);
    }

    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

TEST(extended_acl_mutation_or_nontriviality_is_rejected) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN], helper[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];

    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin))) {
        CHECK(!"ACL fixture creation failed");
        return;
    }
    CHECK((size_t)snprintf(helper, sizeof(helper), "%s/helper", bin) <
          sizeof(helper));
    CHECK(install_self_copy(helper, 0755));

    int acl_rc = change_extended_acl(bin, false);
#if defined(__FreeBSD__)
    /* Some FreeBSD CI filesystems expose no writable ACL namespace. The normal
     * resolver cases still exercise trivial ACL retrieval on O_SEARCH fds; only
     * the nontrivial fixture is unavailable in that environment. */
    if (acl_rc != 0) {
        TS_SKIP("freebsd-acl",
                "filesystem cannot create a nontrivial directory ACL");
    }
#else
    CHECK_EQ_INT(acl_rc, 0);
    if (acl_rc != 0) return;
#endif
    struct stat acl_stat;
    CHECK_EQ_INT(stat(bin, &acl_stat), 0);
    CHECK((acl_stat.st_mode & (S_IWGRP | S_IWOTH)) == 0);
    CHECK_EQ_INT(find_command_path(helper, resolved, sizeof(resolved)), -1);
    CHECK_EQ_INT(change_extended_acl(bin, true), 0);
    CHECK_EQ_INT(find_command_path(helper, resolved, sizeof(resolved)), 0);

    acl_rc = change_extended_acl(helper, false);
#if defined(__FreeBSD__)
    if (acl_rc != 0) {
        TS_SKIP("freebsd-acl",
                "filesystem cannot create a nontrivial leaf ACL");
    }
#else
    CHECK_EQ_INT(acl_rc, 0);
    if (acl_rc != 0) return;
#endif
    CHECK_EQ_INT(stat(helper, &acl_stat), 0);
    CHECK((acl_stat.st_mode & (S_IWGRP | S_IWOTH)) == 0);
    CHECK_EQ_INT(find_command_path(helper, resolved, sizeof(resolved)), -1);
    CHECK_EQ_INT(change_extended_acl(helper, true), 0);
}
#endif

TEST(trusted_system_and_private_user_paths_resolve) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN], helper[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    char *saved_path = NULL;
    bool had_path = false;

    CHECK_EQ_INT(find_command_path("/bin/sh", resolved, sizeof(resolved)), 0);
    CHECK(resolved[0] == '/');
    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin))) {
        CHECK(!"safe fixture creation failed");
        return;
    }
    CHECK((size_t)snprintf(helper, sizeof(helper), "%s/ar07-probe", bin) <
          sizeof(helper));
    CHECK(install_self_copy(helper, 0755));

    save_environment("PATH", &saved_path, &had_path);
    CHECK_EQ_INT(setenv("PATH", bin, 1), 0);
    CHECK_EQ_INT(find_command_path("ar07-probe", resolved,
                                   sizeof(resolved)), 0);
    CHECK_STR_EQ(resolved, helper);
    CHECK_EQ_INT(find_command_path(helper, resolved, sizeof(resolved)), 0);
    CHECK_STR_EQ(resolved, helper);
    restore_environment("PATH", saved_path, had_path);
}

TEST(writable_ancestor_and_unrelated_owner_are_rejected) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN], helper[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];

    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin))) {
        CHECK(!"safe fixture creation failed");
        return;
    }
    CHECK((size_t)snprintf(helper, sizeof(helper), "%s/ar07-owner", bin) <
          sizeof(helper));
    CHECK(install_self_copy(helper, 0755));
    CHECK_EQ_INT(find_command_path(helper, resolved, sizeof(resolved)), 0);

    CHECK_EQ_INT(chmod(root, 0770), 0);
    CHECK_EQ_INT(find_command_path(helper, resolved, sizeof(resolved)), -1);
    CHECK_EQ_INT(chmod(root, 0700), 0);
    CHECK_EQ_INT(chmod(root, 0777), 0);
    CHECK_EQ_INT(find_command_path(helper, resolved, sizeof(resolved)), -1);
    CHECK_EQ_INT(chmod(root, 0700), 0);

    /* An unprivileged test process cannot manufacture an unrelated owner.
     * Root CI exercises the concrete chown branch; elsewhere EPERM itself
     * proves the fixture remained under the positive-control owner. */
    uid_t unrelated = getuid() == (uid_t)1 ? (uid_t)2 : (uid_t)1;
    errno = 0;
    if (chown(helper, unrelated, (gid_t)-1) == 0) {
        CHECK_EQ_INT(find_command_path(helper, resolved,
                                       sizeof(resolved)), -1);
        CHECK_EQ_INT(chown(helper, getuid(), (gid_t)-1), 0);
    } else {
        CHECK(errno == EPERM || errno == EACCES);
    }
}

TEST(every_lookup_revalidates_file_inode_and_parent) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN], helper[MAX_PATH_LEN];
    char replacement[MAX_PATH_LEN], old_bin[MAX_PATH_LEN];
    char resolved[MAX_PATH_LEN];
    struct stat before, after;

    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin))) {
        CHECK(!"safe fixture creation failed");
        return;
    }
    CHECK((size_t)snprintf(helper, sizeof(helper), "%s/ar07-cache", bin) <
          sizeof(helper));
    CHECK((size_t)snprintf(replacement, sizeof(replacement),
                           "%s/replacement", bin) < sizeof(replacement));
    CHECK((size_t)snprintf(old_bin, sizeof(old_bin), "%s/bin-old", root) <
          sizeof(old_bin));
    CHECK(install_self_copy(helper, 0755));
    CHECK_EQ_INT(find_command_path(helper, resolved, sizeof(resolved)), 0);

    CHECK_EQ_INT(chmod(helper, 0775), 0);
    CHECK_EQ_INT(find_command_path(helper, resolved, sizeof(resolved)), -1);
    CHECK_EQ_INT(chmod(helper, 0755), 0);
    CHECK_EQ_INT(find_command_path(helper, resolved, sizeof(resolved)), 0);

    CHECK_EQ_INT(stat(helper, &before), 0);
    CHECK(install_self_copy(replacement, 0775));
    CHECK_EQ_INT(rename(replacement, helper), 0);
    CHECK_EQ_INT(stat(helper, &after), 0);
    CHECK(before.st_dev != after.st_dev || before.st_ino != after.st_ino);
    CHECK_EQ_INT(find_command_path(helper, resolved, sizeof(resolved)), -1);
    CHECK_EQ_INT(chmod(helper, 0755), 0);
    CHECK_EQ_INT(find_command_path(helper, resolved, sizeof(resolved)), 0);

    CHECK_EQ_INT(chmod(bin, 0775), 0);
    CHECK_EQ_INT(find_command_path(helper, resolved, sizeof(resolved)), -1);
    CHECK_EQ_INT(chmod(bin, 0700), 0);
    CHECK_EQ_INT(find_command_path(helper, resolved, sizeof(resolved)), 0);

    /* Replace the complete parent inode after a positive lookup. */
    CHECK_EQ_INT(rename(bin, old_bin), 0);
    CHECK_EQ_INT(mkdir(bin, 0777), 0);
    CHECK_EQ_INT(chmod(bin, 0777), 0);
    CHECK(install_self_copy(helper, 0755));
    CHECK_EQ_INT(find_command_path(helper, resolved, sizeof(resolved)), -1);
}

TEST(symlink_targets_and_lookup_to_exec_swap_are_descriptor_pinned) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN], helper[MAX_PATH_LEN];
    char safe_link[MAX_PATH_LEN], hostile_link[MAX_PATH_LEN];
    char hostile_root[] = "/tmp/gitswitch-ar07-hostile-XXXXXX";
    char hostile_helper[MAX_PATH_LEN], resolved[MAX_PATH_LEN];
    run_result_t result;

    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin)) ||
        !ts_mkdtemp(hostile_root)) {
        CHECK(!"fixture creation failed");
        return;
    }
    CHECK((size_t)snprintf(helper, sizeof(helper), "%s/ar07-race", bin) <
          sizeof(helper));
    CHECK((size_t)snprintf(safe_link, sizeof(safe_link), "%s/ar07-safe-link",
                           bin) < sizeof(safe_link));
    CHECK((size_t)snprintf(hostile_link, sizeof(hostile_link),
                           "%s/ar07-hostile-link", bin) <
          sizeof(hostile_link));
    CHECK((size_t)snprintf(hostile_helper, sizeof(hostile_helper),
                           "%s/probe", hostile_root) <
          sizeof(hostile_helper));
    CHECK_EQ_INT(chmod(hostile_root, 0700), 0);
    CHECK(install_self_copy(helper, 0755));
    CHECK(install_self_copy(hostile_helper, 0755));

    /* Point at the trusted fixture copy rather than depending on where an
     * individual developer happened to build this suite. */
    CHECK_EQ_INT(symlink(helper, safe_link), 0);
    CHECK_EQ_INT(find_command_path(safe_link, resolved, sizeof(resolved)), 0);
    CHECK_STR_EQ(resolved, helper);
    CHECK_EQ_INT(symlink(hostile_helper, hostile_link), 0);
    CHECK_EQ_INT(find_command_path(hostile_link, resolved,
                                   sizeof(resolved)), -1);

    CHECK_EQ_INT(find_command_path("false", g_swap_target,
                                   sizeof(g_swap_target)), 0);
    CHECK_EQ_INT(safe_strncpy(g_swap_expected, helper,
                              sizeof(g_swap_expected)), 0);
    CHECK((size_t)snprintf(g_swap_backup, sizeof(g_swap_backup), "%s.pinned",
                           helper) < sizeof(g_swap_backup));
    g_hook_result = -1;
    run_test_set_exec_resolved_hook(replace_after_pin);
    const char *argv[] = {helper, "--ar07-exec-probe", NULL};
    clear_error();
    int rc = run_argv(argv, NULL, &result);
    run_test_set_exec_resolved_hook(NULL);
    CHECK_EQ_INT(g_hook_result, 0);
    CHECK_EQ_INT(rc, -1);
    CHECK(!result.spawned);
    CHECK_EQ_INT(result.exit_code, -1);
    CHECK(strstr(get_last_error()->message,
                 "changed before launch") != NULL);

    CHECK_EQ_INT(unlink(helper), 0); /* replacement symlink */
    CHECK_EQ_INT(rename(g_swap_backup, helper), 0);
}

TEST(metadata_change_after_pin_fails_before_descriptor_exec) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN], helper[MAX_PATH_LEN];
    run_result_t result;

    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin))) {
        CHECK(!"safe fixture creation failed");
        return;
    }
    CHECK((size_t)snprintf(helper, sizeof(helper), "%s/ar07-chmod-race", bin) <
          sizeof(helper));
    CHECK(install_self_copy(helper, 0755));
    CHECK_EQ_INT(safe_strncpy(g_swap_expected, helper,
                              sizeof(g_swap_expected)), 0);
    g_hook_result = -1;
    run_test_set_exec_resolved_hook(make_pinned_file_group_writable);
    const char *argv[] = {helper, "--ar07-exec-probe", NULL};
    clear_error();
    CHECK_EQ_INT(run_argv(argv, NULL, &result), -1);
    run_test_set_exec_resolved_hook(NULL);
    CHECK_EQ_INT(g_hook_result, 0);
    CHECK(!result.spawned);
    CHECK_EQ_INT(result.exit_code, -1);
    CHECK(strstr(get_last_error()->message,
                 "changed before launch") != NULL);
}

TEST(shebang_env_untrusted_and_recursive_interpreters_are_rejected) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN];
    char env_script[MAX_PATH_LEN], direct_script[MAX_PATH_LEN];
    char recursive_script[MAX_PATH_LEN], recursive_interpreter[MAX_PATH_LEN];
    char env_alias[MAX_PATH_LEN], alias_script[MAX_PATH_LEN];
    char malformed_script[MAX_PATH_LEN], canonical_env[MAX_PATH_LEN];
    char hostile_root[] = "/tmp/gitswitch-ar07-shebang-XXXXXX";
    char hostile_sh[MAX_PATH_LEN], hostile_interpreter[MAX_PATH_LEN];
    char marker[MAX_PATH_LEN], body[MAX_PATH_LEN * 2];
    char path_value[MAX_PATH_LEN * 2];
    char *saved_path = NULL;
    bool had_path = false;
    run_result_t result;

    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin)) ||
        !ts_mkdtemp(hostile_root)) {
        CHECK(!"shebang fixture creation failed");
        return;
    }
    CHECK((size_t)snprintf(env_script, sizeof(env_script), "%s/env-script",
                           bin) < sizeof(env_script));
    CHECK((size_t)snprintf(direct_script, sizeof(direct_script),
                           "%s/direct-script", bin) < sizeof(direct_script));
    CHECK((size_t)snprintf(recursive_script, sizeof(recursive_script),
                           "%s/recursive-script", bin) <
          sizeof(recursive_script));
    CHECK((size_t)snprintf(recursive_interpreter,
                           sizeof(recursive_interpreter), "%s/interpreter",
                           bin) < sizeof(recursive_interpreter));
    CHECK((size_t)snprintf(env_alias, sizeof(env_alias), "%s/env-alias", bin) <
          sizeof(env_alias));
    CHECK((size_t)snprintf(alias_script, sizeof(alias_script),
                           "%s/alias-script", bin) < sizeof(alias_script));
    CHECK((size_t)snprintf(malformed_script, sizeof(malformed_script),
                           "%s/malformed-script", bin) <
          sizeof(malformed_script));
    CHECK((size_t)snprintf(hostile_sh, sizeof(hostile_sh), "%s/sh",
                           hostile_root) < sizeof(hostile_sh));
    CHECK((size_t)snprintf(hostile_interpreter,
                           sizeof(hostile_interpreter), "%s/interpreter",
                           hostile_root) < sizeof(hostile_interpreter));
    CHECK((size_t)snprintf(marker, sizeof(marker), "%s/env-ran",
                           hostile_root) < sizeof(marker));

    CHECK((size_t)snprintf(body, sizeof(body),
                           "#!/bin/sh\n: > '%s'\n", marker) < sizeof(body));
    CHECK_EQ_INT(write_string_to_file(hostile_sh, body, 0755), 0);
    CHECK(install_self_copy(hostile_interpreter, 0755));
    CHECK_EQ_INT(write_string_to_file(
                     env_script, "#!/usr/bin/env sh\nexit 0\n", 0755), 0);
    CHECK((size_t)snprintf(body, sizeof(body), "#!%s\nexit 0\n",
                           hostile_interpreter) < sizeof(body));
    CHECK_EQ_INT(write_string_to_file(direct_script, body, 0755), 0);
    CHECK_EQ_INT(write_string_to_file(
                     recursive_interpreter, "#!/bin/sh\nexit 0\n", 0755), 0);
    CHECK((size_t)snprintf(body, sizeof(body), "#!%s\nexit 0\n",
                           recursive_interpreter) < sizeof(body));
    CHECK_EQ_INT(write_string_to_file(recursive_script, body, 0755), 0);
    CHECK_EQ_INT(find_command_path("env", canonical_env,
                                   sizeof(canonical_env)), 0);
    CHECK_EQ_INT(symlink(canonical_env, env_alias), 0);
    CHECK((size_t)snprintf(body, sizeof(body), "#!%s sh\n: > '%s'\n",
                           env_alias, marker) < sizeof(body));
    CHECK_EQ_INT(write_string_to_file(alias_script, body, 0755), 0);
    static const unsigned char malformed_body[] =
        "#!/bin/sh\0ignored\nexit 0\n";
    CHECK(write_fixture_bytes(malformed_script, malformed_body,
                              sizeof(malformed_body) - 1U, 0755));

    save_environment("PATH", &saved_path, &had_path);
    CHECK((size_t)snprintf(path_value, sizeof(path_value), "%s:/usr/bin:/bin",
                           hostile_root) < sizeof(path_value));
    CHECK_EQ_INT(setenv("PATH", path_value, 1), 0);

    const char *env_argv[] = {env_script, NULL};
    clear_error();
    CHECK_EQ_INT(run_argv(env_argv, NULL, &result), -1);
    CHECK(!result.spawned);
    CHECK(strstr(get_last_error()->message, "shebang") != NULL);
    CHECK(!path_exists(marker));

    const char *alias_argv[] = {alias_script, NULL};
    CHECK_EQ_INT(run_argv(alias_argv, NULL, &result), -1);
    CHECK(!result.spawned);
    CHECK(!path_exists(marker));

    const char *malformed_argv[] = {malformed_script, NULL};
    CHECK_EQ_INT(run_argv(malformed_argv, NULL, &result), -1);
    CHECK(!result.spawned);

    const char *direct_argv[] = {direct_script, NULL};
    CHECK_EQ_INT(run_argv(direct_argv, NULL, &result), -1);
    CHECK(!result.spawned);

    const char *recursive_argv[] = {recursive_script, NULL};
    CHECK_EQ_INT(run_argv(recursive_argv, NULL, &result), -1);
    CHECK(!result.spawned);
    restore_environment("PATH", saved_path, had_path);
}

TEST(probe_and_runner_share_format_and_shebang_eligibility) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN];
    char plain[MAX_PATH_LEN], env_script[MAX_PATH_LEN];
    char untrusted_script[MAX_PATH_LEN], recursive_script[MAX_PATH_LEN];
    char recursive_interpreter[MAX_PATH_LEN], env_alias[MAX_PATH_LEN];
    char alias_script[MAX_PATH_LEN], valid_binary[MAX_PATH_LEN];
    char valid_script[MAX_PATH_LEN], canonical_env[MAX_PATH_LEN];
    char hostile_root[] = "/tmp/gitswitch-ar08-probe-XXXXXX";
    char hostile_interpreter[MAX_PATH_LEN];
    char body[MAX_PATH_LEN * 2], path_value[MAX_PATH_LEN * 2];
    char *saved_path = NULL;
    bool had_path = false;

    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin)) ||
        !ts_mkdtemp(hostile_root)) {
        CHECK(!"probe parity fixture creation failed");
        return;
    }
    CHECK((size_t)snprintf(plain, sizeof(plain), "%s/plain", bin) <
          sizeof(plain));
    CHECK((size_t)snprintf(env_script, sizeof(env_script), "%s/env-script",
                           bin) < sizeof(env_script));
    CHECK((size_t)snprintf(untrusted_script, sizeof(untrusted_script),
                           "%s/untrusted-script", bin) <
          sizeof(untrusted_script));
    CHECK((size_t)snprintf(recursive_script, sizeof(recursive_script),
                           "%s/recursive-script", bin) <
          sizeof(recursive_script));
    CHECK((size_t)snprintf(recursive_interpreter,
                           sizeof(recursive_interpreter), "%s/interpreter",
                           bin) < sizeof(recursive_interpreter));
    CHECK((size_t)snprintf(env_alias, sizeof(env_alias), "%s/env-alias", bin) <
          sizeof(env_alias));
    CHECK((size_t)snprintf(alias_script, sizeof(alias_script),
                           "%s/alias-script", bin) < sizeof(alias_script));
    CHECK((size_t)snprintf(valid_binary, sizeof(valid_binary), "%s/valid-bin",
                           bin) < sizeof(valid_binary));
    CHECK((size_t)snprintf(valid_script, sizeof(valid_script),
                           "%s/valid-script", bin) < sizeof(valid_script));
    CHECK((size_t)snprintf(hostile_interpreter,
                           sizeof(hostile_interpreter), "%s/interpreter",
                           hostile_root) < sizeof(hostile_interpreter));

    CHECK_EQ_INT(write_string_to_file(plain, "exit 0\n", 0755), 0);
    CHECK_EQ_INT(write_string_to_file(
                     env_script, "#!/usr/bin/env sh\nexit 0\n", 0755), 0);
    CHECK(install_self_copy(hostile_interpreter, 0755));
    CHECK((size_t)snprintf(body, sizeof(body), "#!%s\nexit 0\n",
                           hostile_interpreter) < sizeof(body));
    CHECK_EQ_INT(write_string_to_file(untrusted_script, body, 0755), 0);
    CHECK_EQ_INT(write_string_to_file(
                     recursive_interpreter, "#!/bin/sh\nexit 0\n", 0755), 0);
    CHECK((size_t)snprintf(body, sizeof(body), "#!%s\nexit 0\n",
                           recursive_interpreter) < sizeof(body));
    CHECK_EQ_INT(write_string_to_file(recursive_script, body, 0755), 0);
    CHECK_EQ_INT(find_command_path("env", canonical_env,
                                   sizeof(canonical_env)), 0);
    CHECK_EQ_INT(symlink(canonical_env, env_alias), 0);
    CHECK((size_t)snprintf(body, sizeof(body), "#!%s sh\nexit 0\n",
                           env_alias) < sizeof(body));
    CHECK_EQ_INT(write_string_to_file(alias_script, body, 0755), 0);
    CHECK(install_self_copy(valid_binary, 0755));
    CHECK_EQ_INT(write_string_to_file(
                     valid_script, "#!/bin/sh\nexit 0\n", 0755), 0);

    save_environment("PATH", &saved_path, &had_path);
    CHECK((size_t)snprintf(path_value, sizeof(path_value), "%s:/usr/bin:/bin",
                           bin) < sizeof(path_value));
    CHECK_EQ_INT(setenv("PATH", path_value, 1), 0);

    check_probe_and_runner_reject("plain");
    check_probe_and_runner_reject("env-script");
    check_probe_and_runner_reject("untrusted-script");
    check_probe_and_runner_reject("recursive-script");
    check_probe_and_runner_reject("alias-script");
    check_probe_and_runner_accept("valid-bin", "--ar07-exec-probe");
    check_probe_and_runner_accept("valid-script", NULL);

    restore_environment("PATH", saved_path, had_path);
    CHECK_EQ_INT(unlink(hostile_interpreter), 0);
    CHECK_EQ_INT(rmdir(hostile_root), 0);
}

TEST(pinned_direct_interpreter_cannot_be_replaced_at_launch) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN];
    char interpreter[MAX_PATH_LEN], script[MAX_PATH_LEN], body[MAX_PATH_LEN * 2];
    run_result_t result;

    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin))) {
        CHECK(!"interpreter fixture creation failed");
        return;
    }
    CHECK((size_t)snprintf(interpreter, sizeof(interpreter),
                           "%s/ar07-interpreter", bin) < sizeof(interpreter));
    CHECK((size_t)snprintf(script, sizeof(script), "%s/ar07-script", bin) <
          sizeof(script));
    CHECK(install_self_copy(interpreter, 0755));
    CHECK((size_t)snprintf(body, sizeof(body), "#!%s\nexit 99\n",
                           interpreter) < sizeof(body));
    CHECK_EQ_INT(write_string_to_file(script, body, 0755), 0);
    CHECK_EQ_INT(find_command_path("false", g_swap_target,
                                   sizeof(g_swap_target)), 0);
    CHECK_EQ_INT(safe_strncpy(g_swap_expected, interpreter,
                              sizeof(g_swap_expected)), 0);
    CHECK((size_t)snprintf(g_swap_backup, sizeof(g_swap_backup), "%s.pinned",
                           interpreter) < sizeof(g_swap_backup));

    g_hook_result = -1;
    run_test_set_exec_resolved_hook(replace_interpreter_after_pin);
    const char *argv[] = {script, NULL};
    clear_error();
    int rc = run_argv(argv, NULL, &result);
    run_test_set_exec_resolved_hook(NULL);
    CHECK_EQ_INT(g_hook_result, 0);
    CHECK_EQ_INT(rc, -1);
    CHECK(!result.spawned);
    CHECK_EQ_INT(result.exit_code, -1);
    CHECK(strstr(get_last_error()->message,
                 "changed before launch") != NULL);

    CHECK_EQ_INT(unlink(interpreter), 0);
    CHECK_EQ_INT(rename(g_swap_backup, interpreter), 0);
}

TEST(nonregular_leaf_is_bounded) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN];
    char fifo_path[MAX_PATH_LEN];
    int status = 0;

    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin))) {
        CHECK(!"leaf fixture creation failed");
        return;
    }
    CHECK((size_t)snprintf(fifo_path, sizeof(fifo_path), "%s/fifo", bin) <
          sizeof(fifo_path));
    CHECK_EQ_INT(mkfifo(fifo_path, 0755), 0);

    /* The worker/deadline turns any accidental blocking FIFO open into a
     * bounded test failure instead of a hung suite. */
    pid_t worker = fork();
    CHECK(worker >= 0);
    if (worker < 0) return;
    if (worker == 0) {
        const char *argv[] = {fifo_path, NULL};
        run_result_t result;
        int rc = run_argv(argv, NULL, &result);
        _exit(rc == -1 && !result.spawned ? 0 : 1);
    }
    CHECK(reap_within(worker, 1000, &status));
    CHECK(WIFEXITED(status));
    if (WIFEXITED(status)) CHECK_EQ_INT(WEXITSTATUS(status), 0);
}

#if defined(__linux__) || defined(__FreeBSD__)
TEST(execute_only_policy_is_explicit) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN];
    char helper[MAX_PATH_LEN], resolved[MAX_PATH_LEN];

    if (getuid() == (uid_t)0) {
        TS_SKIP("unprivileged",
                "execute-only permission checks are ineffective as root");
    }
    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin))) {
        CHECK(!"execute-only fixture creation failed");
        return;
    }
    CHECK((size_t)snprintf(helper, sizeof(helper), "%s/helper", bin) <
          sizeof(helper));
    CHECK(install_self_copy(helper, 0755));

    /* Linux O_PATH and FreeBSD O_SEARCH permit a genuinely search-only
     * trusted ancestor: the owner has execute but no read permission. */
    CHECK_EQ_INT(chmod(bin, 0111), 0);
    CHECK_EQ_INT(find_command_path(helper, resolved, sizeof(resolved)), 0);

    /* The conservative format policy requires read+execute permission: an
     * unreadable file might be a script with an unvalidated shebang. */
    CHECK_EQ_INT(chmod(helper, 0111), 0);
    CHECK_EQ_INT(find_command_path(helper, resolved, sizeof(resolved)), -1);
    const char *argv[] = {helper, "--ar07-exec-probe", NULL};
    run_result_t result;
    CHECK_EQ_INT(run_argv(argv, NULL, &result), -1);
    CHECK(!result.spawned);
    CHECK_EQ_INT(chmod(bin, 0700), 0);
}
#endif

TEST(trusted_shebang_executes_from_the_verified_descriptor) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN], script[MAX_PATH_LEN];
    char body[512];
    run_result_t result;

    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin))) {
        CHECK(!"safe fixture creation failed");
        return;
    }
    CHECK((size_t)snprintf(script, sizeof(script), "%s/ar07-script", bin) <
          sizeof(script));
#if defined(__linux__)
    const char *script_fd_path = "/proc/self/fd/4";
#else
    const char *script_fd_path = "/dev/fd/4";
#endif
    CHECK((size_t)snprintf(
              body, sizeof(body),
              "#!/bin/sh -e\n[ \"$1\" = payload ]\n"
              "[ \"$0\" = \"%s\" ]\n",
              script_fd_path) < sizeof(body));
    CHECK_EQ_INT(write_string_to_file(script, body, 0755), 0);
    const char *argv[] = {script, "payload", NULL};
    CHECK_EQ_INT(run_argv(argv, NULL, &result), 0);
    CHECK(result.spawned);
    CHECK_EQ_INT(result.exit_code, 0);
}

static void check_fatal_path_candidate_errno(int injected_errno) {
    char *saved_path = NULL;
    bool had_path = false;
    const char *argv[] = {"true", NULL};
    run_result_t result;

    save_environment("PATH", &saved_path, &had_path);
    CHECK_EQ_INT(setenv("PATH", "/ar11-definitely-missing:/usr/bin:/bin", 1),
                 0);
    run_test_set_path_candidate_failure(1, injected_errno);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, NULL, &result), -1);
    CHECK(!result.spawned);
    CHECK_EQ_INT(errno, injected_errno);
    CHECK_EQ_INT(get_last_error()->code, ERR_SYSTEM_CALL);
    run_test_set_path_candidate_failure(0, 0);
    restore_environment("PATH", saved_path, had_path);
}

TEST(path_candidate_operational_failures_are_fatal) {
    check_fatal_path_candidate_errno(EIO);
    check_fatal_path_candidate_errno(EMFILE);
    check_fatal_path_candidate_errno(ESTALE);
}

TEST(inner_directory_open_failure_survives_successful_policy_probe) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN], configured_path[MAX_PATH_LEN];
    char *saved_path = NULL;
    bool had_path = false;
    const char *argv[] = {"true", NULL};
    run_result_t result;

    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin))) {
        CHECK(!"inner directory-open fixture creation failed");
        return;
    }
    CHECK((size_t)snprintf(configured_path, sizeof(configured_path),
                           "%s:/usr/bin:/bin", bin) <
          sizeof(configured_path));
    save_environment("PATH", &saved_path, &had_path);
    CHECK_EQ_INT(setenv("PATH", configured_path, 1), 0);

    /* #1 opens '/'; #2 opens the first real ancestor. Its injected EIO is
     * followed by a successful no-follow stat of that same ancestor, proving
     * the secondary policy probe cannot erase the operational failure and
     * redirect execution to /usr/bin/true. */
    run_test_set_directory_open_failure(2, EIO);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, NULL, &result), -1);
    CHECK(!result.spawned);
    CHECK_EQ_INT(errno, EIO);
    CHECK_EQ_INT(get_last_error()->code, ERR_SYSTEM_CALL);
    CHECK_EQ_INT(get_last_error()->system_errno, EIO);
    run_test_set_directory_open_failure(0, 0);
    restore_environment("PATH", saved_path, had_path);
}

static void check_acl_failure_stops_path_fallback(
    run_test_exec_acl_target_t target, int injected_errno) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN], helper[MAX_PATH_LEN];
    char configured_path[MAX_PATH_LEN];
    char *saved_path = NULL;
    bool had_path = false;
    const char *argv[] = {"true", NULL};
    run_result_t result;

    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin))) {
        CHECK(!"ACL failure fixture creation failed");
        return;
    }
    CHECK((size_t)snprintf(helper, sizeof(helper), "%s/true", bin) <
          sizeof(helper));
    CHECK_EQ_INT(write_string_to_file(helper, "#!/bin/sh\nexit 97\n", 0755),
                 0);
    CHECK((size_t)snprintf(configured_path, sizeof(configured_path),
                           "%s:/usr/bin:/bin", bin) <
          sizeof(configured_path));
    save_environment("PATH", &saved_path, &had_path);
    CHECK_EQ_INT(setenv("PATH", configured_path, 1), 0);

    run_test_set_exec_acl_failure(target, injected_errno);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, NULL, &result), -1);
    CHECK(!result.spawned);
    CHECK_EQ_INT(errno, injected_errno);
    CHECK_EQ_INT(get_last_error()->code, ERR_SYSTEM_CALL);
    CHECK_EQ_INT(get_last_error()->system_errno, injected_errno);
    run_test_set_exec_acl_failure(RUN_TEST_EXEC_ACL_NONE, 0);
    restore_environment("PATH", saved_path, had_path);
}

TEST(exec_acl_operational_failures_stop_path_fallback) {
    check_acl_failure_stops_path_fallback(RUN_TEST_EXEC_ACL_DIRECTORY, EIO);
    check_acl_failure_stops_path_fallback(RUN_TEST_EXEC_ACL_LEAF, EMFILE);
}

static void check_acl_policy_rejection_is_skippable(
    run_test_exec_acl_target_t target) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN], helper[MAX_PATH_LEN];
    char configured_path[MAX_PATH_LEN];
    char *saved_path = NULL;
    bool had_path = false;
    const char *argv[] = {"true", NULL};
    run_result_t result;

    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin))) {
        CHECK(!"ACL policy fixture creation failed");
        return;
    }
    CHECK((size_t)snprintf(helper, sizeof(helper), "%s/true", bin) <
          sizeof(helper));
    CHECK_EQ_INT(write_string_to_file(helper, "#!/bin/sh\nexit 97\n", 0755),
                 0);
    CHECK((size_t)snprintf(configured_path, sizeof(configured_path),
                           "%s:/usr/bin:/bin", bin) <
          sizeof(configured_path));
    save_environment("PATH", &saved_path, &had_path);
    CHECK_EQ_INT(setenv("PATH", configured_path, 1), 0);

    run_test_set_exec_acl_failure(target, EACCES);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, NULL, &result), 0);
    CHECK(result.spawned);
    CHECK_EQ_INT(result.exit_code, 0);
    run_test_set_exec_acl_failure(RUN_TEST_EXEC_ACL_NONE, 0);
    restore_environment("PATH", saved_path, had_path);
}

TEST(exec_acl_policy_rejection_continues_path_search) {
    check_acl_policy_rejection_is_skippable(RUN_TEST_EXEC_ACL_DIRECTORY);
    check_acl_policy_rejection_is_skippable(RUN_TEST_EXEC_ACL_LEAF);
}

TEST(path_absence_and_policy_rejection_continue_deterministically) {
    char *saved_path = NULL;
    bool had_path = false;
    const char *argv[] = {"true", NULL};
    run_result_t result;

    save_environment("PATH", &saved_path, &had_path);
    /* Seed a fatal stale errno: the world-writable /tmp entry must replace it
     * with deterministic EACCES and permit the trusted later entry. */
    CHECK_EQ_INT(setenv("PATH", "/ar11-definitely-missing:/tmp:/usr/bin:/bin",
                        1),
                 0);
    errno = EIO;
    CHECK_EQ_INT(run_argv(argv, NULL, &result), 0);
    CHECK(result.spawned);
    CHECK_EQ_INT(result.exit_code, 0);
    restore_environment("PATH", saved_path, had_path);
}

TEST(interpreter_parser_io_failure_preserves_operational_truth) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN], script[MAX_PATH_LEN];
    char malformed[MAX_PATH_LEN];
    const char *argv[2];
    run_result_t result;

    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin))) {
        CHECK(!"interpreter parser fixture creation failed");
        return;
    }
    CHECK((size_t)snprintf(script, sizeof(script), "%s/ar11-script", bin) <
          sizeof(script));
    CHECK((size_t)snprintf(malformed, sizeof(malformed), "%s/ar11-malformed",
                           bin) < sizeof(malformed));
    CHECK_EQ_INT(write_string_to_file(script, "#!/bin/sh\nexit 0\n", 0755),
                 0);
    argv[0] = script;
    argv[1] = NULL;

    run_test_set_exec_parse_failure(2, EIO);
    clear_error();
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, NULL, &result), -1);
    CHECK(!result.spawned);
    CHECK_EQ_INT(errno, EIO);
    CHECK_EQ_INT(get_last_error()->code, ERR_SYSTEM_CALL);
    CHECK_EQ_INT(get_last_error()->system_errno, EIO);
    CHECK(strstr(get_last_error()->message, "inspect executable format") !=
          NULL);
    run_test_set_exec_parse_failure(0, 0);

    CHECK_EQ_INT(write_string_to_file(malformed, "not a binary or script\n",
                                      0755),
                 0);
    argv[0] = malformed;
    clear_error();
    errno = 0;
    CHECK_EQ_INT(run_argv(argv, NULL, &result), -1);
    CHECK(!result.spawned);
    CHECK_EQ_INT(errno, ENOEXEC);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);
}

TEST(runtime_root_is_absolute_private_and_cwd_independent) {
    char root[MAX_PATH_LEN], bin[MAX_PATH_LEN], runtime[MAX_PATH_LEN];
    char link_path[MAX_PATH_LEN], missing[MAX_PATH_LEN];
    char fallback[MAX_PATH_LEN], observed[MAX_PATH_LEN];
    char variant[MAX_PATH_LEN], rejected[MAX_PATH_LEN];
    char old_cwd[MAX_PATH_LEN];
    struct stat fallback_fd_stat, fallback_path_stat;
    char *saved_xdg = NULL;
    bool had_xdg = false;
    int fd;

    if (!make_safe_fixture(root, sizeof(root), bin, sizeof(bin)) ||
        !getcwd(old_cwd, sizeof(old_cwd))) {
        CHECK(!"fixture/cwd creation failed");
        return;
    }
    CHECK((size_t)snprintf(runtime, sizeof(runtime), "%s/runtime", root) <
          sizeof(runtime));
    CHECK((size_t)snprintf(link_path, sizeof(link_path), "%s/runtime-link",
                           root) < sizeof(link_path));
    CHECK((size_t)snprintf(missing, sizeof(missing), "%s/missing", root) <
          sizeof(missing));
    CHECK_EQ_INT(mkdir(runtime, 0700), 0);
    save_environment("XDG_RUNTIME_DIR", &saved_xdg, &had_xdg);

    CHECK_EQ_INT(unsetenv("XDG_RUNTIME_DIR"), 0);
    fd = open_runtime_parent(fallback, sizeof(fallback));
    CHECK(fd >= 0);
    CHECK(fallback[0] == '/');
    CHECK_EQ_INT(fstat(fd, &fallback_fd_stat), 0);
    CHECK_EQ_INT(stat(fallback, &fallback_path_stat), 0);
    CHECK(fallback_fd_stat.st_dev == fallback_path_stat.st_dev &&
          fallback_fd_stat.st_ino == fallback_path_stat.st_ino);
    if (fd >= 0) close(fd);

    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", "", 1), 0);
    fd = open_runtime_parent(observed, sizeof(observed));
    CHECK(fd >= 0);
    CHECK_STR_EQ(observed, fallback);
    if (fd >= 0) close(fd);

    CHECK_EQ_INT(chdir(root), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", "runtime", 1), 0);
    clear_error();
    CHECK_EQ_INT(open_runtime_parent(observed, sizeof(observed)), -1);
    CHECK(strstr(get_last_error()->message, "absolute path") != NULL);
    CHECK_EQ_INT(chdir("/"), 0);
    clear_error();
    CHECK_EQ_INT(open_runtime_parent(observed, sizeof(observed)), -1);
    CHECK(strstr(get_last_error()->message, "absolute path") != NULL);
    CHECK_EQ_INT(chdir(old_cwd), 0);

    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);
    fd = open_runtime_parent(observed, sizeof(observed));
    CHECK(fd >= 0);
    CHECK_STR_EQ(observed, runtime);
    if (fd >= 0) close(fd);

    CHECK_EQ_INT(chmod(runtime, 0000), 0);
    clear_error();
    CHECK_EQ_INT(open_runtime_parent(observed, sizeof(observed)), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_FILE_IO);
    CHECK_EQ_INT(chmod(runtime, 0700), 0);
    CHECK_EQ_INT(symlink(runtime, link_path), 0);

    /* Trailing separators and dot components must not make lstat/open follow
     * a final symlink that the bare spelling rejects. */
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", link_path, 1), 0);
    CHECK_EQ_INT(open_runtime_parent(rejected, sizeof(rejected)), -1);
    CHECK((size_t)snprintf(variant, sizeof(variant), "%s/", link_path) <
          sizeof(variant));
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", variant, 1), 0);
    CHECK_EQ_INT(open_runtime_parent(rejected, sizeof(rejected)), -1);
    CHECK((size_t)snprintf(variant, sizeof(variant), "%s/.", link_path) <
          sizeof(variant));
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", variant, 1), 0);
    CHECK_EQ_INT(open_runtime_parent(rejected, sizeof(rejected)), -1);

    /* A configured nonempty root is authoritative: absence must fail closed,
     * while creating that exact directory makes the same configuration usable. */
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", missing, 1), 0);
    clear_error();
    fd = open_runtime_parent(observed, sizeof(observed));
    CHECK_EQ_INT(fd, -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_FILE_IO);
    CHECK_EQ_INT(mkdir(missing, 0700), 0);
    clear_error();
    fd = open_runtime_parent(observed, sizeof(observed));
    CHECK(fd >= 0);
    CHECK_STR_EQ(observed, missing);
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);
    if (fd >= 0) close(fd);

    restore_environment("XDG_RUNTIME_DIR", saved_xdg, had_xdg);
}

int main(int argc, char **argv) {
    const char *program = argc > 0 ? strrchr(argv[0], '/') : NULL;
    program = program ? program + 1 : (argc > 0 ? argv[0] : "");
    if (strcmp(program, "ar07-interpreter") == 0) {
        errno = 0;
        return fcntl(STDERR_FILENO + 3, F_GETFD, 0) == -1 && errno == EBADF
                   ? 0 : 5;
    }
    if (argc == 2 && strcmp(argv[1], "--ar07-exec-probe") == 0) return 0;
    if (argc != 1 || !realpath(argv[0], g_self_path)) {
        fprintf(stderr, "test_ar07_exec_trust: cannot resolve own executable\n");
        return 2;
    }
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(long_trusted_home_fixtures_are_tracked_without_path_cap);
#if defined(__APPLE__) || defined(__FreeBSD__)
    RUN_TEST(extended_acl_mutation_or_nontriviality_is_rejected);
#endif
    RUN_TEST(trusted_system_and_private_user_paths_resolve);
    RUN_TEST(writable_ancestor_and_unrelated_owner_are_rejected);
    RUN_TEST(every_lookup_revalidates_file_inode_and_parent);
    RUN_TEST(symlink_targets_and_lookup_to_exec_swap_are_descriptor_pinned);
    RUN_TEST(metadata_change_after_pin_fails_before_descriptor_exec);
    RUN_TEST(shebang_env_untrusted_and_recursive_interpreters_are_rejected);
    RUN_TEST(probe_and_runner_share_format_and_shebang_eligibility);
    RUN_TEST(pinned_direct_interpreter_cannot_be_replaced_at_launch);
    RUN_TEST(nonregular_leaf_is_bounded);
#if defined(__linux__) || defined(__FreeBSD__)
    RUN_TEST(execute_only_policy_is_explicit);
#endif
    RUN_TEST(trusted_shebang_executes_from_the_verified_descriptor);
    RUN_TEST(path_candidate_operational_failures_are_fatal);
    RUN_TEST(inner_directory_open_failure_survives_successful_policy_probe);
    RUN_TEST(exec_acl_operational_failures_stop_path_fallback);
    RUN_TEST(exec_acl_policy_rejection_continues_path_search);
    RUN_TEST(path_absence_and_policy_rejection_continue_deterministically);
    RUN_TEST(interpreter_parser_io_failure_preserves_operational_truth);
    RUN_TEST(runtime_root_is_absolute_private_and_cwd_independent);
    return ts_test_finish();
}
