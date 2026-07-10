/* Security regression tests: command arguments must never reach a shell.
 * These freeze the audit's C1 fix (ssh-add path injection), the
 * find_command_path no-shell behavior, the PS-1/PS-2 PATH supply-chain
 * hardening, and the fd-CLOEXEC child fd hygiene. */
#include "test.h"
#include "gitswitch.h"
#include "utils.h"
#include "error.h"
#include "ssh_manager.h"
#include "git_ops.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Recording runner: captures the argv vector instead of executing anything. */
static char rec_argv[16][512];
static int rec_argc;

static int recording_runner(const char *const argv[], const run_opts_t *opts,
                            run_result_t *result) {
    (void)opts;
    rec_argc = 0;
    for (int i = 0; argv[i] != NULL && i < 16; i++) {
        strncpy(rec_argv[i], argv[i], sizeof(rec_argv[i]) - 1);
        rec_argv[i][sizeof(rec_argv[i]) - 1] = '\0';
        rec_argc++;
    }
    if (result) {
        result->spawned = true;
        result->exit_code = 0;
        result->term_signal = 0;
        result->out_len = 0;
    }
    return 0;
}

/* The C1 vulnerability: an ssh_key path with shell metacharacters. With argv
 * execution it must arrive as a SINGLE, intact argv element — never split or
 * interpreted by a shell. */
TEST(ssh_add_key_path_is_one_argv_element) {
    ssh_config_t cfg;
    const char *payload = "/home/u/.ssh/k';touch /tmp/PWNED;'";
    command_runner_fn prev;
    int rc;

    memset(&cfg, 0, sizeof(cfg));
    safe_strncpy(cfg.agent_socket_path, "/tmp/dummy-agent.sock", sizeof(cfg.agent_socket_path));

    prev = run_set_runner(recording_runner);
    rc = ssh_add_key(&cfg, payload);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT(rec_argc, 2);              /* {"ssh-add", payload} */
    CHECK_STR_EQ(rec_argv[0], "ssh-add");
    CHECK_STR_EQ(rec_argv[1], payload);     /* intact: no shell splitting */
}

/* find_command_path must resolve via a PATH walk (no shell); a name containing
 * shell metacharacters must simply not resolve and must not execute anything. */
TEST(find_command_path_rejects_metachars) {
    char buf[256];
    CHECK_EQ_INT(find_command_path("x; touch /tmp/gs_pwned_marker", buf, sizeof(buf)), -1);
}

TEST(find_command_path_finds_real_binary) {
    char buf[256];
    CHECK_EQ_INT(find_command_path("echo", buf, sizeof(buf)), 0);
    CHECK(buf[0] == '/');
}

TEST(command_exists_basic) {
    CHECK(command_exists("echo"));
    CHECK(!command_exists("gitswitch_no_such_command_xyz"));
}

/* ---- PS-1/PS-2 PATH supply-chain hardening -------------------------------
 *
 * Helpers: build throwaway PATH directories with controlled permissions and
 * drop marker-touching shell scripts into them. A resolved-and-executed shadow
 * binary would create its marker file; the checks below assert it never runs. */

static char saved_path_env[4096];

static void save_path(void) {
    const char *p = getenv("PATH");
    snprintf(saved_path_env, sizeof(saved_path_env), "%s", p ? p : "");
}

static void restore_path(void) {
    setenv("PATH", saved_path_env, 1);
}

/* mkdtemp + explicit chmod (not umask-clipped); returns 0 on success. */
static int make_test_dir(char *out, size_t out_size, mode_t mode) {
    char tmpl[] = "/tmp/gs_sec_XXXXXX";
    if (!mkdtemp(tmpl)) return -1;
    if (chmod(tmpl, mode) != 0) return -1;
    snprintf(out, out_size, "%s", tmpl);
    return 0;
}

/* Install <dir>/<name> as an executable sh script that touches marker_path. */
static int install_fake_tool(const char *dir, const char *name,
                             const char *marker_path,
                             char *tool_out, size_t tool_out_size) {
    char body[1024];
    if ((size_t)snprintf(tool_out, tool_out_size, "%s/%s", dir, name) >= tool_out_size) {
        return -1;
    }
    snprintf(body, sizeof(body), "#!/bin/sh\ntouch '%s'\n", marker_path);
    return write_string_to_file(tool_out, body, 0755);
}

static void remove_test_dir(const char *dir, const char *tool, const char *marker) {
    if (tool) unlink(tool);
    if (marker) unlink(marker);
    rmdir(dir);
}

/* A shadow binary in a world-writable PATH entry must not resolve, and must
 * not hide the real binary in the standard dirs behind it. */
TEST(find_command_path_skips_world_writable_dir) {
    char wwdir[256], tool[512], echo_shadow[512], marker[512], buf[512];
    char new_path[1024];

    if (make_test_dir(wwdir, sizeof(wwdir), 0777) != 0) { CHECK(!"mkdtemp failed"); return; }
    snprintf(marker, sizeof(marker), "%s/marker", wwdir);
    CHECK_EQ_INT(install_fake_tool(wwdir, "gs_fake_ww_tool", marker, tool, sizeof(tool)), 0);
    CHECK_EQ_INT(install_fake_tool(wwdir, "echo", marker, echo_shadow, sizeof(echo_shadow)), 0);

    save_path();
    snprintf(new_path, sizeof(new_path), "%s:/usr/bin:/bin", wwdir);
    setenv("PATH", new_path, 1);

    /* Only exists in the o+w dir: must not resolve at all. */
    CHECK_EQ_INT(find_command_path("gs_fake_ww_tool", buf, sizeof(buf)), -1);
    /* Shadowed common tool: must resolve, but to the real one, not the shadow. */
    CHECK_EQ_INT(find_command_path("echo", buf, sizeof(buf)), 0);
    CHECK(strncmp(buf, wwdir, strlen(wwdir)) != 0);

    restore_path();
    unlink(echo_shadow);
    remove_test_dir(wwdir, tool, marker);
}

/* AR-04 M5: group write permission is enough to make either a PATH directory
 * or the candidate helper mutable by someone other than the invoking user.
 * Exercise both common group-write modes and retain positive controls for
 * ordinary private/user and system-style permissions. */
TEST(find_command_path_rejects_group_writable_components) {
    char d770[256], d775[256], f770dir[256], f775dir[256];
    char ok700dir[256], ok755dir[256];
    char d770tool[512], d775tool[512], f770tool[512], f775tool[512];
    char ok700tool[512], ok755tool[512];
    char marker[6][512], buf[512], path[512];

    if (make_test_dir(d770, sizeof(d770), 0770) != 0 ||
        make_test_dir(d775, sizeof(d775), 0775) != 0 ||
        make_test_dir(f770dir, sizeof(f770dir), 0755) != 0 ||
        make_test_dir(f775dir, sizeof(f775dir), 0755) != 0 ||
        make_test_dir(ok700dir, sizeof(ok700dir), 0700) != 0 ||
        make_test_dir(ok755dir, sizeof(ok755dir), 0755) != 0) {
        CHECK(!"mkdtemp failed");
        return;
    }

    snprintf(marker[0], sizeof(marker[0]), "%s/marker", d770);
    snprintf(marker[1], sizeof(marker[1]), "%s/marker", d775);
    snprintf(marker[2], sizeof(marker[2]), "%s/marker", f770dir);
    snprintf(marker[3], sizeof(marker[3]), "%s/marker", f775dir);
    snprintf(marker[4], sizeof(marker[4]), "%s/marker", ok700dir);
    snprintf(marker[5], sizeof(marker[5]), "%s/marker", ok755dir);
    CHECK_EQ_INT(install_fake_tool(d770, "gs_fake_dir770", marker[0],
                                   d770tool, sizeof(d770tool)), 0);
    CHECK_EQ_INT(install_fake_tool(d775, "gs_fake_dir775", marker[1],
                                   d775tool, sizeof(d775tool)), 0);
    CHECK_EQ_INT(install_fake_tool(f770dir, "gs_fake_file770", marker[2],
                                   f770tool, sizeof(f770tool)), 0);
    CHECK_EQ_INT(chmod(f770tool, 0770), 0);
    CHECK_EQ_INT(install_fake_tool(f775dir, "gs_fake_file775", marker[3],
                                   f775tool, sizeof(f775tool)), 0);
    CHECK_EQ_INT(chmod(f775tool, 0775), 0);
    CHECK_EQ_INT(install_fake_tool(ok700dir, "gs_fake_ok700", marker[4],
                                   ok700tool, sizeof(ok700tool)), 0);
    CHECK_EQ_INT(chmod(ok700tool, 0700), 0);
    CHECK_EQ_INT(install_fake_tool(ok755dir, "gs_fake_ok755", marker[5],
                                   ok755tool, sizeof(ok755tool)), 0);

    save_path();

    snprintf(path, sizeof(path), "%s", d770);
    setenv("PATH", path, 1);
    CHECK_EQ_INT(find_command_path("gs_fake_dir770", buf, sizeof(buf)), -1);
    CHECK(!command_exists("gs_fake_dir770")); /* same lookup used by doctor */
    CHECK_EQ_INT(find_command_path(d770tool, buf, sizeof(buf)), -1);

    snprintf(path, sizeof(path), "%s", d775);
    setenv("PATH", path, 1);
    CHECK_EQ_INT(find_command_path("gs_fake_dir775", buf, sizeof(buf)), -1);

    snprintf(path, sizeof(path), "%s", f770dir);
    setenv("PATH", path, 1);
    CHECK_EQ_INT(find_command_path("gs_fake_file770", buf, sizeof(buf)), -1);
    CHECK_EQ_INT(find_command_path(f770tool, buf, sizeof(buf)), -1);

    snprintf(path, sizeof(path), "%s", f775dir);
    setenv("PATH", path, 1);
    CHECK_EQ_INT(find_command_path("gs_fake_file775", buf, sizeof(buf)), -1);

    snprintf(path, sizeof(path), "%s", ok700dir);
    setenv("PATH", path, 1);
    CHECK_EQ_INT(find_command_path("gs_fake_ok700", buf, sizeof(buf)), 0);
    CHECK_STR_EQ(buf, ok700tool);

    snprintf(path, sizeof(path), "%s", ok755dir);
    setenv("PATH", path, 1);
    CHECK_EQ_INT(find_command_path("gs_fake_ok755", buf, sizeof(buf)), 0);
    CHECK_STR_EQ(buf, ok755tool);

    restore_path();
    remove_test_dir(d770, d770tool, marker[0]);
    remove_test_dir(d775, d775tool, marker[1]);
    remove_test_dir(f770dir, f770tool, marker[2]);
    remove_test_dir(f775dir, f775tool, marker[3]);
    remove_test_dir(ok700dir, ok700tool, marker[4]);
    remove_test_dir(ok755dir, ok755tool, marker[5]);
}

/* Relative ("."), bare-name ("bin"), and empty ("::") PATH entries all resolve
 * against the CWD — inside a cloned repo that is attacker territory, so they
 * are refused. An explicit relative path with a slash is refused too. */
TEST(find_command_path_skips_relative_and_empty_entries) {
    char dir[256], tool[512], marker[512], buf[512], oldcwd[512];

    if (make_test_dir(dir, sizeof(dir), 0700) != 0) { CHECK(!"mkdtemp failed"); return; }
    snprintf(marker, sizeof(marker), "%s/marker", dir);
    CHECK_EQ_INT(install_fake_tool(dir, "gs_fake_rel_tool", marker, tool, sizeof(tool)), 0);

    CHECK(getcwd(oldcwd, sizeof(oldcwd)) != NULL);
    CHECK_EQ_INT(chdir(dir), 0);
    save_path();

    setenv("PATH", ".:/usr/bin:/bin", 1);
    CHECK_EQ_INT(find_command_path("gs_fake_rel_tool", buf, sizeof(buf)), -1);

    setenv("PATH", ":/usr/bin:/bin", 1); /* leading empty entry == CWD */
    CHECK_EQ_INT(find_command_path("gs_fake_rel_tool", buf, sizeof(buf)), -1);

    /* Explicit relative path: refused even though the file exists and is +x. */
    CHECK_EQ_INT(find_command_path("./gs_fake_rel_tool", buf, sizeof(buf)), -1);

    /* ... and the marker never appeared, i.e. nothing executed it. */
    CHECK(!path_exists(marker));

    restore_path();
    CHECK_EQ_INT(chdir(oldcwd), 0);
    remove_test_dir(dir, tool, marker);
}

/* Legitimate setups must keep working: a user-owned, non-world-writable
 * absolute dir (~/.local/bin, /opt/homebrew/bin, a Nix profile) supplies its
 * binary; an explicit absolute path to a system binary resolves. */
TEST(find_command_path_allows_user_owned_absolute_dir) {
    char dir[256], tool[512], marker[512], buf[512];
    char new_path[1024];

    if (make_test_dir(dir, sizeof(dir), 0755) != 0) { CHECK(!"mkdtemp failed"); return; }
    snprintf(marker, sizeof(marker), "%s/marker", dir);
    CHECK_EQ_INT(install_fake_tool(dir, "gs_fake_ok_tool", marker, tool, sizeof(tool)), 0);

    save_path();
    snprintf(new_path, sizeof(new_path), "%s:/usr/bin:/bin", dir);
    setenv("PATH", new_path, 1);

    CHECK_EQ_INT(find_command_path("gs_fake_ok_tool", buf, sizeof(buf)), 0);
    CHECK_STR_EQ(buf, tool);

    /* Explicit absolute path to a trusted system binary still resolves. */
    CHECK_EQ_INT(find_command_path("/bin/sh", buf, sizeof(buf)), 0);

    restore_path();
    remove_test_dir(dir, tool, marker);
}

/* Acceptance repro for PS-1: a fake tool planted in a world-writable PATH
 * entry must never be executed by run_argv (no marker file), while the same
 * tool in a trusted dir runs fine (positive control proving the marker
 * mechanism works). */
TEST(run_argv_never_executes_from_world_writable_dir) {
    char wwdir[256], okdir[256], wwtool[512], oktool[512];
    char wwmarker[512], okmarker[512], new_path[1024];
    run_result_t res;
    const char *argv[] = {"gs_fake_marker_tool", NULL};

    if (make_test_dir(wwdir, sizeof(wwdir), 0777) != 0) { CHECK(!"mkdtemp failed"); return; }
    if (make_test_dir(okdir, sizeof(okdir), 0755) != 0) {
        CHECK(!"mkdtemp failed");
        rmdir(wwdir);
        return;
    }
    snprintf(wwmarker, sizeof(wwmarker), "%s/marker", wwdir);
    snprintf(okmarker, sizeof(okmarker), "%s/marker", okdir);
    CHECK_EQ_INT(install_fake_tool(wwdir, "gs_fake_marker_tool", wwmarker, wwtool, sizeof(wwtool)), 0);
    CHECK_EQ_INT(install_fake_tool(okdir, "gs_fake_marker_tool", okmarker, oktool, sizeof(oktool)), 0);

    save_path();

    /* Attack: o+w dir first in PATH. Fails closed before fork; no marker. */
    snprintf(new_path, sizeof(new_path), "%s:/usr/bin:/bin", wwdir);
    setenv("PATH", new_path, 1);
    CHECK_EQ_INT(run_argv(argv, NULL, &res), -1);
    CHECK(!res.spawned);
    CHECK(!path_exists(wwmarker));

    /* Control: same tool in a trusted dir executes and leaves its marker. */
    snprintf(new_path, sizeof(new_path), "%s:/usr/bin:/bin", okdir);
    setenv("PATH", new_path, 1);
    CHECK_EQ_INT(run_argv(argv, NULL, &res), 0);
    CHECK(path_exists(okmarker));

    restore_path();
    remove_test_dir(wwdir, wwtool, wwmarker);
    remove_test_dir(okdir, oktool, okmarker);
}

TEST(run_argv_never_executes_group_writable_helper) {
    char dir[256], tool[512], marker[512];
    run_result_t res;
    const char *argv[] = {"gs_fake_group_writable_tool", NULL};

    if (make_test_dir(dir, sizeof(dir), 0755) != 0) {
        CHECK(!"mkdtemp failed");
        return;
    }
    snprintf(marker, sizeof(marker), "%s/marker", dir);
    CHECK_EQ_INT(install_fake_tool(dir, "gs_fake_group_writable_tool", marker,
                                   tool, sizeof(tool)), 0);
    CHECK_EQ_INT(chmod(tool, 0770), 0);

    save_path();
    setenv("PATH", dir, 1);
    CHECK_EQ_INT(run_argv(argv, NULL, &res), -1);
    CHECK(!res.spawned);
    CHECK(!path_exists(marker));
    restore_path();

    remove_test_dir(dir, tool, marker);
}

#if defined(__linux__)
/* fd-CLOEXEC acceptance: a child spawned via run_argv must see nothing beyond
 * stdin/stdout/stderr, even when the parent deliberately leaked a non-CLOEXEC
 * fd. Listing /proc/self/fd is Linux-only; fd 3 in the output is ls's own
 * handle on the /proc/self/fd directory itself. */
TEST(run_argv_child_sees_only_std_fds) {
    const char *argv[] = {"sh", "-c", "ls /proc/self/fd", NULL};
    char out[512];
    run_opts_t opts;
    run_result_t res;
    char *save = NULL;

    int leaked = open("/dev/null", O_RDWR); /* deliberately no O_CLOEXEC */
    CHECK(leaked >= 0);
    /* Pin a second leak to a high number so it can't be mistaken for the
     * transient fd 3 that ls itself opens. */
    CHECK_EQ_INT(dup2(leaked, 222), 222);

    memset(&opts, 0, sizeof(opts));
    opts.out = out;
    opts.out_size = sizeof(out);
    CHECK_EQ_INT(run_argv(argv, &opts, &res), 0);

    for (char *tok = strtok_r(out, " \t\n", &save); tok;
         tok = strtok_r(NULL, " \t\n", &save)) {
        CHECK(atoi(tok) <= 3);
    }

    close(222);
    if (leaked >= 0) close(leaked);
}
#endif

/* git config values are written via argv (no shell), so a legitimate display
 * name with spaces and parentheses must be ACCEPTED (regression for the switch
 * that failed on "Jane Doe (Work)"). git_set_config_value validates before it
 * invokes the runner, so an accepted value reaches the recording runner. */
TEST(git_config_value_allows_parenthesized_name) {
    command_runner_fn prev = run_set_runner(recording_runner);
    int rc = git_set_config_value("user.name", "Jane Doe (Work)", GIT_SCOPE_GLOBAL);
    run_set_runner(prev);
    CHECK_EQ_INT(rc, 0);
    CHECK_STR_EQ(rec_argv[rec_argc - 1], "Jane Doe (Work)"); /* intact, one argv element */
}

/* But genuinely unsafe values are still rejected before the runner runs: a
 * leading '-' (git could read it as an option) and control characters. */
TEST(git_config_value_rejects_dangerous) {
    command_runner_fn prev = run_set_runner(recording_runner);
    int rc_dash = git_set_config_value("user.name", "-oProxyCommand=x", GIT_SCOPE_GLOBAL);
    int rc_ctrl = git_set_config_value("user.name", "a\nb", GIT_SCOPE_GLOBAL);
    run_set_runner(prev);
    CHECK_EQ_INT(rc_dash, -1);
    CHECK_EQ_INT(rc_ctrl, -1);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(ssh_add_key_path_is_one_argv_element);
    RUN_TEST(find_command_path_rejects_metachars);
    RUN_TEST(find_command_path_finds_real_binary);
    RUN_TEST(command_exists_basic);
    RUN_TEST(find_command_path_skips_world_writable_dir);
    RUN_TEST(find_command_path_rejects_group_writable_components);
    RUN_TEST(find_command_path_skips_relative_and_empty_entries);
    RUN_TEST(find_command_path_allows_user_owned_absolute_dir);
    RUN_TEST(run_argv_never_executes_from_world_writable_dir);
    RUN_TEST(run_argv_never_executes_group_writable_helper);
#if defined(__linux__)
    RUN_TEST(run_argv_child_sees_only_std_fds);
#endif
    RUN_TEST(git_config_value_allows_parenthesized_name);
    RUN_TEST(git_config_value_rejects_dangerous);
TEST_MAIN_END()
