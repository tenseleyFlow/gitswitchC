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
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>

bool runtime_entry_test_may_be_replaced(
    uid_t uid, mode_t parent_mode, uid_t parent_uid,
    bool parent_acl_trusted, uid_t child_uid, bool child_acl_trusted,
    bool child_owner_can_add_delete_acl);

typedef void (*create_directory_test_hook_fn)(int stage, const char *path);
create_directory_test_hook_fn gitswitch_test_set_create_directory_hook(
    create_directory_test_hook_fn hook);

enum {
    CREATE_DIRECTORY_TEST_AFTER_FINAL_OPEN = 1
};

static const char *g_create_race_parent;
static const char *g_create_race_moved;
static int g_create_race_calls;
static int g_create_race_error;

static void replace_created_directory_parent(int stage, const char *path) {
    (void)path;
    if (stage != CREATE_DIRECTORY_TEST_AFTER_FINAL_OPEN) return;
    g_create_race_calls++;
    if (!g_create_race_parent || !g_create_race_moved ||
        rename(g_create_race_parent, g_create_race_moved) != 0 ||
        mkdir(g_create_race_parent, 0700) != 0) {
        g_create_race_error = errno ? errno : EIO;
    }
}

/* Recording runner: captures the argv vector instead of executing anything. */
static char rec_argv[16][512];
static int rec_argc;
static int rec_calls;

static int recording_runner(const char *const argv[], const run_opts_t *opts,
                            run_result_t *result) {
    (void)opts;
    rec_calls++;
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

/* ssh_add_key is deliberately a low-level one-command compatibility primitive:
 * it neither validates nor reopens the pathname. Even a nonexistent path with
 * shell metacharacters must reach one ssh-add invocation as one intact argv
 * element, with the runner's result defining success. */
TEST(ssh_add_key_low_level_contract_is_one_unvalidated_argv) {
    ssh_config_t cfg;
    const char *payload = "/home/u/.ssh/k';touch /tmp/PWNED;'";
    command_runner_fn prev;
    int rc;

    memset(&cfg, 0, sizeof(cfg));
    safe_strncpy(cfg.agent_socket_path, "/tmp/dummy-agent.sock", sizeof(cfg.agent_socket_path));

    rec_calls = 0;
    prev = run_set_runner(recording_runner);
    rc = ssh_add_key(&cfg, payload);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT(rec_calls, 1);
    CHECK_EQ_INT(rec_argc, 3);              /* {"ssh-add", "-k", payload} */
    CHECK_STR_EQ(rec_argv[0], "ssh-add");
    CHECK_STR_EQ(rec_argv[1], "-k");        /* no sibling certificate */
    CHECK_STR_EQ(rec_argv[2], payload);     /* intact: no shell splitting */
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

/* Executable-trust fixtures must start below a non-replaceable ancestor.
 * /tmp itself is 01777 and AR-07 M28 correctly rejects every helper beneath
 * it even when the immediate mkdtemp leaf is 0700, so place these particular
 * PATH fixtures below the user's private home instead. */
static int make_test_dir(char *out, size_t out_size, mode_t mode) {
    char tmpl[MAX_PATH_LEN];
    if (!ts_mkdtemp_trusted(tmpl, sizeof(tmpl), "gs-sec")) return -1;
    if (chmod(tmpl, mode) != 0) return -1;
    if ((size_t)snprintf(out, out_size, "%s", tmpl) >= out_size) return -1;
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
    /* Shell redirection is a builtin, so the positive control remains valid
     * even when PATH intentionally contains only the trusted fixture dir. */
    snprintf(body, sizeof(body), "#!/bin/sh\n: > '%s'\n", marker_path);
    return write_string_to_file(tool_out, body, 0755);
}

static void remove_test_dir(const char *dir, const char *tool, const char *marker) {
    if (tool) unlink(tool);
    if (marker) unlink(marker);
    rmdir(dir);
}

/* Permission changes must apply to the object already opened, not a pathname
 * that could name something else by the time chmod runs. These functional
 * checks also preserve the helpers' exact-mode and copy-mode contracts. */
TEST(file_helpers_apply_descriptor_permissions) {
    char root[] = "/tmp/gs_file_mode_XXXXXX";
    char src[512], dst[512], content[64];
    struct stat st;

    if (!ts_mkdtemp(root)) { CHECK(!"mkdtemp failed"); return; }
    snprintf(src, sizeof(src), "%s/source", root);
    snprintf(dst, sizeof(dst), "%s/destination", root);

    CHECK_EQ_INT(write_string_to_file(src, "pinned permissions\n", 0640), 0);
    CHECK_EQ_INT(stat(src, &st), 0);
    CHECK_EQ_INT(st.st_mode & 0777, 0640);

    CHECK_EQ_INT(copy_file(src, dst), 0);
    CHECK_EQ_INT(stat(dst, &st), 0);
    CHECK_EQ_INT(st.st_mode & 0777, 0640);
    CHECK(read_file_to_string(dst, content, sizeof(content)) >= 0);
    CHECK_STR_EQ(content, "pinned permissions\n");

    unlink(dst);
    unlink(src);
    rmdir(root);
}

TEST(ensure_private_dir_contract_matches_adoption_policy) {
    char root[] = "/tmp/gs_private_dir_XXXXXX";
    char created_dir[512], private_dir[512], file_path[512], link_path[512];
    struct stat st;

    if (!ts_mkdtemp(root)) { CHECK(!"mkdtemp failed"); return; }
    snprintf(created_dir, sizeof(created_dir), "%s/created", root);
    snprintf(private_dir, sizeof(private_dir), "%s/private", root);
    snprintf(file_path, sizeof(file_path), "%s/file", root);
    snprintf(link_path, sizeof(link_path), "%s/link", root);

    /* Absent paths are created as private directories. */
    CHECK_EQ_INT(ensure_private_dir(created_dir), 0);
    CHECK_EQ_INT(lstat(created_dir, &st), 0);
    CHECK(S_ISDIR(st.st_mode));
    CHECK_EQ_INT(st.st_mode & 0777, 0700);

    /* Existing safe modes are accepted without being broadened to 0700. */
    CHECK_EQ_INT(chmod(created_dir, 0500), 0);
    CHECK_EQ_INT(ensure_private_dir(created_dir), 0);
    CHECK_EQ_INT(lstat(created_dir, &st), 0);
    CHECK_EQ_INT(st.st_mode & 0777, 0500);

    /* On platforms with pinned no-follow directory descriptors, an existing
     * self-owned permissive directory is safely adopted and tightened. */
    CHECK_EQ_INT(mkdir(private_dir, 0700), 0);
    CHECK_EQ_INT(chmod(private_dir, 0777), 0);
#if defined(O_NOFOLLOW) && defined(O_DIRECTORY)
    CHECK_EQ_INT(ensure_private_dir(private_dir), 0);
    CHECK_EQ_INT(lstat(private_dir, &st), 0);
    CHECK(S_ISDIR(st.st_mode));
    CHECK_EQ_INT(st.st_mode & 0777, 0700);
#else
    CHECK_EQ_INT(ensure_private_dir(private_dir), -1);
    clear_error();
#endif

    /* Non-directories and final-component symlinks are always refused. */
    CHECK_EQ_INT(write_string_to_file(file_path, "not a directory\n", 0600), 0);
    CHECK_EQ_INT(ensure_private_dir(file_path), -1);
    clear_error();
    CHECK_EQ_INT(symlink(private_dir, link_path), 0);
    CHECK_EQ_INT(ensure_private_dir(link_path), -1);
    clear_error();

    unlink(link_path);
    unlink(file_path);
    chmod(created_dir, 0700);
    rmdir(created_dir);
    rmdir(private_dir);
    rmdir(root);
}

TEST(create_directory_recursive_validates_every_component_and_symlink_policy) {
    char root[] = "/tmp/gs_mkdir_walk_XXXXXX";
    char nested[512], repeated[512], regular[512], regular_child[512];
    char fifo_path[512], fifo_child[512], target[512], link_path[512];
    char link_child[512], final_link[512];
    struct stat st;

    if (!ts_mkdtemp(root)) { CHECK(!"mkdtemp failed"); return; }
    snprintf(nested, sizeof(nested), "%s/a/b", root);
    snprintf(repeated, sizeof(repeated), "%s//repeated///leaf///", root);
    snprintf(regular, sizeof(regular), "%s/regular", root);
    snprintf(regular_child, sizeof(regular_child), "%s/regular/child", root);
    snprintf(fifo_path, sizeof(fifo_path), "%s/fifo", root);
    snprintf(fifo_child, sizeof(fifo_child), "%s/fifo/child", root);
    snprintf(target, sizeof(target), "%s/target", root);
    snprintf(link_path, sizeof(link_path), "%s/link", root);
    snprintf(link_child, sizeof(link_child), "%s/link/child", root);
    snprintf(final_link, sizeof(final_link), "%s/final-link", root);

    CHECK_EQ_INT(create_directory_recursive("/", 0700), 0);
    CHECK_EQ_INT(create_directory_recursive(nested, 0700), 0);
    CHECK_EQ_INT(create_directory_recursive(nested, 0700), 0);
    CHECK_EQ_INT(stat(nested, &st), 0);
    CHECK(S_ISDIR(st.st_mode));
    CHECK_EQ_INT(create_directory_recursive(repeated, 0700), 0);

    CHECK_EQ_INT(write_string_to_file(regular, "file", 0600), 0);
    CHECK_EQ_INT(create_directory_recursive(regular, 0700), -1);
    CHECK_EQ_INT(create_directory_recursive(regular_child, 0700), -1);
    CHECK_EQ_INT(mkfifo(fifo_path, 0600), 0);
    CHECK_EQ_INT(create_directory_recursive(fifo_path, 0700), -1);
    CHECK_EQ_INT(create_directory_recursive(fifo_child, 0700), -1);

    CHECK_EQ_INT(mkdir(target, 0700), 0);
    CHECK_EQ_INT(symlink(target, link_path), 0);
    CHECK_EQ_INT(create_directory_recursive(link_child, 0700), 0);
    CHECK_EQ_INT(stat(link_child, &st), 0);
    CHECK(S_ISDIR(st.st_mode));
    CHECK_EQ_INT(symlink(target, final_link), 0);
    CHECK_EQ_INT(create_directory_recursive(final_link, 0700), -1);
}

TEST(create_directory_recursive_detects_ancestor_replacement) {
    char root[] = "/tmp/gs_mkdir_replace_XXXXXX";
    char parent[512], moved[512], path[512];

    if (!ts_mkdtemp(root)) { CHECK(!"mkdtemp failed"); return; }
    snprintf(parent, sizeof(parent), "%s/parent", root);
    snprintf(moved, sizeof(moved), "%s/moved", root);
    snprintf(path, sizeof(path), "%s/parent/leaf", root);
    CHECK_EQ_INT(mkdir(parent, 0700), 0);
    g_create_race_parent = parent;
    g_create_race_moved = moved;
    g_create_race_calls = 0;
    g_create_race_error = 0;
    (void)gitswitch_test_set_create_directory_hook(
        replace_created_directory_parent);
    CHECK_EQ_INT(create_directory_recursive(path, 0700), -1);
    (void)gitswitch_test_set_create_directory_hook(NULL);
    g_create_race_parent = NULL;
    g_create_race_moved = NULL;
    CHECK_EQ_INT(g_create_race_calls, 1);
    CHECK_EQ_INT(g_create_race_error, 0);
    CHECK_EQ_INT(get_last_error()->code, ERR_FILE_IO);
}

/* AR-05 L13: the runtime lock is non-blocking — a contender while another
 * writer holds it must be EXCLUDED IMMEDIATELY (fail fast with a contention
 * error) instead of waiting behind an unbounded passphrase/PIN prompt, and
 * must acquire normally once the holder releases. Mutual exclusion is what
 * matters: no two writers ever hold it concurrently. */
TEST(runtime_state_lock_excludes_shared_xdg_writers_fail_fast) {
    char runtime[] = "/tmp/gs_runtime_lock_XXXXXX";
    char lock_dir[512], lock_path[512];
    char saved_xdg[MAX_PATH_LEN] = "";
    const char *old_xdg = getenv("XDG_RUNTIME_DIR");
    bool had_xdg = old_xdg && *old_xdg;
    struct pollfd pfd;
    int pipefd[2] = {-1, -1};
    int parent_lock = -1;
    pid_t child = -1;
    int status = 0;
    char marker = '\0';
    int poll_rc;

    if (had_xdg) safe_strncpy(saved_xdg, old_xdg, sizeof(saved_xdg));
    if (!ts_mkdtemp(runtime)) { CHECK(!"mkdtemp failed"); return; }
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);
    parent_lock = runtime_state_lock_acquire();
    CHECK(parent_lock >= 0);
    CHECK_EQ_INT(pipe(pipefd), 0);
    if (parent_lock < 0 || pipefd[0] < 0) goto cleanup;

    fflush(NULL);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        int child_lock;

        close(pipefd[0]);
        close(parent_lock); /* drop the inherited reference to the parent lock */
        child_lock = runtime_state_lock_acquire();
        if (child_lock >= 0) {
            /* Acquired concurrently with the live holder: exclusion broken. */
            runtime_state_lock_release(child_lock);
            if (write(pipefd[1], "X", 1) != 1) _exit(4);
            _exit(2);
        }
        if (write(pipefd[1], "B", 1) != 1) _exit(3);
        _exit(0);
    }
    if (child < 0) goto cleanup;
    close(pipefd[1]);
    pipefd[1] = -1;

    /* The contender must resolve promptly WHILE the lock is still held —
     * a 2s silence means it blocked (the old behavior). */
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = pipefd[0];
    pfd.events = POLLIN;
    do {
        poll_rc = poll(&pfd, 1, 2000);
    } while (poll_rc < 0 && errno == EINTR);
    CHECK(poll_rc > 0 && (pfd.revents & POLLIN) != 0);
    if (poll_rc > 0 && (pfd.revents & POLLIN) != 0) {
        CHECK_EQ_INT(read(pipefd[0], &marker, 1), 1);
        CHECK_EQ_INT(marker, 'B');
    } else {
        (void)kill(child, SIGKILL);
    }
    CHECK_EQ_INT(waitpid(child, &status, 0), child);
    child = -1;
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* Once the holder releases, a fresh contender must acquire. */
    runtime_state_lock_release(parent_lock);
    parent_lock = -1;
    fflush(NULL);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        int child_lock = runtime_state_lock_acquire();
        if (child_lock < 0) _exit(2);
        runtime_state_lock_release(child_lock);
        _exit(0);
    }
    if (child < 0) goto cleanup;
    CHECK_EQ_INT(waitpid(child, &status, 0), child);
    child = -1;
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

cleanup:
    if (parent_lock >= 0) runtime_state_lock_release(parent_lock);
    if (child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
    }
    if (pipefd[0] >= 0) close(pipefd[0]);
    if (pipefd[1] >= 0) close(pipefd[1]);
    snprintf(lock_path, sizeof(lock_path), "%s/gitswitch-runtime/.lock", runtime);
    snprintf(lock_dir, sizeof(lock_dir), "%s/gitswitch-runtime", runtime);
    (void)unlink(lock_path);
    (void)rmdir(lock_dir);
    (void)rmdir(runtime);
    if (had_xdg) {
        CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", saved_xdg, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("XDG_RUNTIME_DIR"), 0);
    }
}

TEST(runtime_state_lock_rejects_unsafe_xdg_runtime_dir) {
    char runtime[] = "/tmp/gs_runtime_unsafe_XXXXXX";
    char real_dir[512], other_dir[512], xdg_dir[512], other_xdg_dir[512];
    char link_path[512], intermediate_path[512];
    char real_lock_dir[640], real_lock_path[768];
    char other_lock_dir[640], other_lock_path[768];
    char saved_xdg[MAX_PATH_LEN] = "";
    const char *old_xdg = getenv("XDG_RUNTIME_DIR");
    bool had_xdg = old_xdg && *old_xdg;
    int lock_fd = -1;

    if (had_xdg) safe_strncpy(saved_xdg, old_xdg, sizeof(saved_xdg));
    if (!ts_mkdtemp(runtime)) { CHECK(!"mkdtemp failed"); return; }

    CHECK_EQ_INT(chmod(runtime, 0755), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);
    CHECK_EQ_INT(runtime_state_lock_acquire(), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);
    clear_error();

    CHECK_EQ_INT(chmod(runtime, 0700), 0);
    snprintf(real_dir, sizeof(real_dir), "%s/real", runtime);
    snprintf(link_path, sizeof(link_path), "%s/link", runtime);
    CHECK_EQ_INT(mkdir(real_dir, 0700), 0);
    CHECK_EQ_INT(symlink(real_dir, link_path), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", link_path, 1), 0);
    CHECK_EQ_INT(runtime_state_lock_acquire(), -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);
    clear_error();

    (void)unlink(link_path);
    CHECK((size_t)snprintf(other_dir, sizeof(other_dir), "%s/other",
                           runtime) < sizeof(other_dir));
    CHECK((size_t)snprintf(xdg_dir, sizeof(xdg_dir), "%s/xdg",
                           real_dir) < sizeof(xdg_dir));
    CHECK((size_t)snprintf(other_xdg_dir, sizeof(other_xdg_dir), "%s/xdg",
                           other_dir) < sizeof(other_xdg_dir));
    CHECK((size_t)snprintf(intermediate_path, sizeof(intermediate_path),
                           "%s/xdg", link_path) < sizeof(intermediate_path));
    CHECK((size_t)snprintf(real_lock_dir, sizeof(real_lock_dir),
                           "%s/gitswitch-runtime", xdg_dir) <
          sizeof(real_lock_dir));
    CHECK((size_t)snprintf(real_lock_path, sizeof(real_lock_path), "%s/.lock",
                           real_lock_dir) < sizeof(real_lock_path));
    CHECK((size_t)snprintf(other_lock_dir, sizeof(other_lock_dir),
                           "%s/gitswitch-runtime", other_xdg_dir) <
          sizeof(other_lock_dir));
    CHECK((size_t)snprintf(other_lock_path, sizeof(other_lock_path), "%s/.lock",
                           other_lock_dir) < sizeof(other_lock_path));
    CHECK_EQ_INT(mkdir(other_dir, 0700), 0);
    CHECK_EQ_INT(mkdir(xdg_dir, 0700), 0);
    CHECK_EQ_INT(mkdir(other_xdg_dir, 0700), 0);
    CHECK_EQ_INT(symlink(real_dir, link_path), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", intermediate_path, 1), 0);
    lock_fd = runtime_state_lock_acquire();
    CHECK_EQ_INT(lock_fd, -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);
    if (lock_fd >= 0) {
        runtime_state_lock_release(lock_fd);
        lock_fd = -1;
    }
    clear_error();

    CHECK_EQ_INT(unlink(link_path), 0);
    CHECK_EQ_INT(symlink(other_dir, link_path), 0);
    lock_fd = runtime_state_lock_acquire();
    CHECK_EQ_INT(lock_fd, -1);
    CHECK_EQ_INT(get_last_error()->code, ERR_PERMISSION_DENIED);
    if (lock_fd >= 0) runtime_state_lock_release(lock_fd);

    (void)unlink(link_path);
    (void)unlink(other_lock_path);
    (void)rmdir(other_lock_dir);
    (void)unlink(real_lock_path);
    (void)rmdir(real_lock_dir);
    (void)rmdir(other_xdg_dir);
    (void)rmdir(xdg_dir);
    (void)rmdir(other_dir);
    (void)rmdir(real_dir);
    (void)rmdir(runtime);
    if (had_xdg) {
        CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", saved_xdg, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("XDG_RUNTIME_DIR"), 0);
    }
}

TEST(runtime_entry_replacement_classification_is_lifetime_safe) {
    const uid_t acting_uid = (uid_t)4242;
    const uid_t other_uid = (uid_t)4343;

    /* Directory owners can chmod a presently read-only ancestor and then
     * replace its child while a transaction is live. */
    CHECK(runtime_entry_test_may_be_replaced(
        acting_uid, 0500, acting_uid, true, other_uid, true, false));

    /* BSD-family/NFSv4 ACLs can grant deletion on the child independently of
     * an otherwise immutable parent. Unknown/nontrivial child ACLs anchor. */
    CHECK(runtime_entry_test_may_be_replaced(
        acting_uid, 0555, other_uid, true, other_uid, false, false));

    /* On ACL_DELETE-capable systems a child owner can make a currently
     * trivial ACL mutable later, so ownership itself requires an anchor. */
    CHECK(runtime_entry_test_may_be_replaced(
        acting_uid, 0555, other_uid, true, acting_uid, true, true));

    /* A non-owned, read-only parent and trivial ACLs need no extra anchor. */
    CHECK(!runtime_entry_test_may_be_replaced(
        acting_uid, 0555, other_uid, true, other_uid, true, false));
}

TEST(runtime_state_lock_excludes_contender_after_ancestor_replacement) {
    char root[] = "/tmp/gs_runtime_ancestor_XXXXXX";
    char moved[512], branch[512], xdg[512], lock_dir[640], lock_path[768];
    char old_branch[512], old_xdg[512], old_lock_dir[640], old_lock_path[768];
    char saved_xdg[MAX_PATH_LEN] = "";
    const char *previous_xdg = getenv("XDG_RUNTIME_DIR");
    bool had_xdg = previous_xdg && *previous_xdg;
    struct pollfd pfd;
    int entered[2] = {-1, -1};
    int holder = -1;
    pid_t child = -1;
    int status = 0;
    int poll_rc;
    char marker = '\0';

    if (had_xdg) safe_strncpy(saved_xdg, previous_xdg, sizeof(saved_xdg));
    if (!ts_mkdtemp(root)) { CHECK(!"mkdtemp failed"); return; }
    CHECK((size_t)snprintf(moved, sizeof(moved), "%s.old", root) <
          sizeof(moved));
    CHECK((size_t)snprintf(branch, sizeof(branch), "%s/branch", root) <
          sizeof(branch));
    CHECK((size_t)snprintf(xdg, sizeof(xdg), "%s/xdg", branch) <
          sizeof(xdg));
    CHECK((size_t)snprintf(lock_dir, sizeof(lock_dir),
                           "%s/gitswitch-runtime", xdg) < sizeof(lock_dir));
    CHECK((size_t)snprintf(lock_path, sizeof(lock_path), "%s/.lock",
                           lock_dir) < sizeof(lock_path));
    CHECK((size_t)snprintf(old_branch, sizeof(old_branch), "%s/branch",
                           moved) < sizeof(old_branch));
    CHECK((size_t)snprintf(old_xdg, sizeof(old_xdg), "%s/xdg", old_branch) <
          sizeof(old_xdg));
    CHECK((size_t)snprintf(old_lock_dir, sizeof(old_lock_dir),
                           "%s/gitswitch-runtime", old_xdg) <
          sizeof(old_lock_dir));
    CHECK((size_t)snprintf(old_lock_path, sizeof(old_lock_path), "%s/.lock",
                           old_lock_dir) < sizeof(old_lock_path));
    CHECK_EQ_INT(mkdir(branch, 0700), 0);
    CHECK_EQ_INT(mkdir(xdg, 0700), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", xdg, 1), 0);

    holder = runtime_state_lock_acquire();
    CHECK(holder >= 0);
    CHECK_EQ_INT(rename(root, moved), 0);
    CHECK_EQ_INT(mkdir(root, 0700), 0);
    CHECK_EQ_INT(mkdir(branch, 0700), 0);
    CHECK_EQ_INT(mkdir(xdg, 0700), 0);
    CHECK_EQ_INT(pipe(entered), 0);
    if (holder < 0 || entered[0] < 0) goto cleanup;

    fflush(NULL);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        int child_lock;

        close(entered[0]);
        close(holder);
        child_lock = runtime_state_lock_acquire();
        if (child_lock >= 0) {
            runtime_state_lock_release(child_lock);
            if (write(entered[1], "X", 1) != 1) _exit(4);
            _exit(2);
        }
        if (write(entered[1], "B", 1) != 1) _exit(3);
        _exit(0);
    }
    if (child < 0) goto cleanup;
    close(entered[1]);
    entered[1] = -1;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = entered[0];
    pfd.events = POLLIN;
    do {
        poll_rc = poll(&pfd, 1, 2000);
    } while (poll_rc < 0 && errno == EINTR);
    CHECK(poll_rc > 0 && (pfd.revents & POLLIN) != 0);
    if (poll_rc > 0 && (pfd.revents & POLLIN) != 0) {
        CHECK_EQ_INT(read(entered[0], &marker, 1), 1);
        CHECK_EQ_INT(marker, 'B');
    } else {
        (void)kill(child, SIGKILL);
    }
    CHECK_EQ_INT(waitpid(child, &status, 0), child);
    child = -1;
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    runtime_state_lock_release(holder);
    holder = -1;
    fflush(NULL);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        int child_lock = runtime_state_lock_acquire();
        if (child_lock < 0) _exit(2);
        runtime_state_lock_release(child_lock);
        _exit(0);
    }
    if (child < 0) goto cleanup;
    CHECK_EQ_INT(waitpid(child, &status, 0), child);
    child = -1;
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

cleanup:
    if (holder >= 0) runtime_state_lock_release(holder);
    if (child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
    }
    if (entered[0] >= 0) close(entered[0]);
    if (entered[1] >= 0) close(entered[1]);
    (void)unlink(lock_path);
    (void)rmdir(lock_dir);
    (void)rmdir(xdg);
    (void)rmdir(branch);
    (void)rmdir(root);
    (void)unlink(old_lock_path);
    (void)rmdir(old_lock_dir);
    (void)rmdir(old_xdg);
    (void)rmdir(old_branch);
    (void)rmdir(moved);
    if (had_xdg) {
        CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", saved_xdg, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("XDG_RUNTIME_DIR"), 0);
    }
}

/* A waiter pins the original runtime directory before blocking on its lock.
 * Replacing the public directory while it waits must make acquisition fail;
 * accepting either namespace would split writers across two different locks. */
TEST(runtime_state_lock_rejects_namespace_replacement_while_waiting) {
    char runtime[] = "/tmp/gs_runtime_swap_XXXXXX";
    char lock_dir[512], moved_dir[512], old_lock[640], new_lock[640];
    char saved_xdg[MAX_PATH_LEN] = "";
    const char *old_xdg = getenv("XDG_RUNTIME_DIR");
    bool had_xdg = old_xdg && *old_xdg;
    struct timespec settle = { .tv_sec = 0, .tv_nsec = 300000000 };
    int ready[2] = {-1, -1};
    int parent_lock = -1;
    pid_t child = -1;
    int status = 0;
    char marker;

    if (had_xdg) safe_strncpy(saved_xdg, old_xdg, sizeof(saved_xdg));
    if (!ts_mkdtemp(runtime)) { CHECK(!"mkdtemp failed"); return; }
    CHECK_EQ_INT(chmod(runtime, 0700), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);
    snprintf(lock_dir, sizeof(lock_dir), "%s/gitswitch-runtime", runtime);
    snprintf(moved_dir, sizeof(moved_dir), "%s/gitswitch-runtime.old", runtime);
    snprintf(old_lock, sizeof(old_lock), "%s/.lock", moved_dir);
    snprintf(new_lock, sizeof(new_lock), "%s/.lock", lock_dir);

    parent_lock = runtime_state_lock_acquire();
    CHECK(parent_lock >= 0);
    CHECK_EQ_INT(pipe(ready), 0);
    if (parent_lock < 0 || ready[0] < 0) goto cleanup;

    fflush(NULL);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        int child_lock;
        close(ready[0]);
        close(parent_lock);
        if (write(ready[1], "R", 1) != 1) _exit(9);
        child_lock = runtime_state_lock_acquire();
        if (child_lock >= 0) {
            runtime_state_lock_release(child_lock);
            _exit(2);
        }
        _exit(0);
    }
    if (child < 0) goto cleanup;
    close(ready[1]);
    ready[1] = -1;
    CHECK_EQ_INT(read(ready[0], &marker, 1), 1);
    CHECK_EQ_INT(marker, 'R');
    (void)nanosleep(&settle, NULL);

    CHECK_EQ_INT(rename(lock_dir, moved_dir), 0);
    CHECK_EQ_INT(mkdir(lock_dir, 0700), 0);
    runtime_state_lock_release(parent_lock);
    parent_lock = -1;

    CHECK_EQ_INT(waitpid(child, &status, 0), child);
    child = -1;
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

cleanup:
    if (parent_lock >= 0) runtime_state_lock_release(parent_lock);
    if (child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
    }
    if (ready[0] >= 0) close(ready[0]);
    if (ready[1] >= 0) close(ready[1]);
    (void)unlink(new_lock);
    (void)rmdir(lock_dir);
    (void)unlink(old_lock);
    (void)rmdir(moved_dir);
    (void)rmdir(runtime);
    if (had_xdg) {
        CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", saved_xdg, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("XDG_RUNTIME_DIR"), 0);
    }
}

/* A contender created after the public leaf is replaced must still be
 * excluded by the original holder.  The pinned parent-directory lock is the
 * stable namespace anchor shared by both the old and replacement leaves —
 * accepting the replacement leaf would split writers across two locks. With
 * the non-blocking acquisition (AR-05 L13) exclusion now manifests as an
 * immediate contention failure rather than a wait. */
TEST(runtime_state_lock_excludes_contender_after_leaf_replacement) {
    char runtime[] = "/tmp/gs_runtime_postswap_XXXXXX";
    char lock_dir[512], moved_dir[512], old_lock[640], new_lock[640];
    char saved_xdg[MAX_PATH_LEN] = "";
    const char *old_xdg = getenv("XDG_RUNTIME_DIR");
    bool had_xdg = old_xdg && *old_xdg;
    struct pollfd pfd;
    int entered[2] = {-1, -1};
    int parent_lock = -1;
    pid_t child = -1;
    int status = 0;
    int poll_rc;
    char marker = '\0';

    if (had_xdg) safe_strncpy(saved_xdg, old_xdg, sizeof(saved_xdg));
    if (!ts_mkdtemp(runtime)) { CHECK(!"mkdtemp failed"); return; }
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);
    snprintf(lock_dir, sizeof(lock_dir), "%s/gitswitch-runtime", runtime);
    snprintf(moved_dir, sizeof(moved_dir), "%s/gitswitch-runtime.old", runtime);
    snprintf(old_lock, sizeof(old_lock), "%s/.lock", moved_dir);
    snprintf(new_lock, sizeof(new_lock), "%s/.lock", lock_dir);

    parent_lock = runtime_state_lock_acquire();
    CHECK(parent_lock >= 0);
    CHECK_EQ_INT(rename(lock_dir, moved_dir), 0);
    CHECK_EQ_INT(mkdir(lock_dir, 0700), 0);
    CHECK_EQ_INT(pipe(entered), 0);
    if (parent_lock < 0 || entered[0] < 0) goto cleanup;

    fflush(NULL);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        int child_lock;

        close(entered[0]);
        close(parent_lock);
        child_lock = runtime_state_lock_acquire();
        if (child_lock >= 0) {
            /* Entered concurrently via the replacement leaf: anchor broken. */
            runtime_state_lock_release(child_lock);
            if (write(entered[1], "X", 1) != 1) _exit(4);
            _exit(2);
        }
        if (write(entered[1], "B", 1) != 1) _exit(3);
        _exit(0);
    }
    if (child < 0) goto cleanup;
    close(entered[1]);
    entered[1] = -1;

    /* The contender must be rejected promptly while the original holder is
     * live — silence means it blocked (old behavior) or entered concurrently. */
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = entered[0];
    pfd.events = POLLIN;
    do {
        poll_rc = poll(&pfd, 1, 2000);
    } while (poll_rc < 0 && errno == EINTR);
    CHECK(poll_rc > 0 && (pfd.revents & POLLIN) != 0);
    if (poll_rc > 0 && (pfd.revents & POLLIN) != 0) {
        CHECK_EQ_INT(read(entered[0], &marker, 1), 1);
        CHECK_EQ_INT(marker, 'B');
    } else {
        (void)kill(child, SIGKILL);
    }
    CHECK_EQ_INT(waitpid(child, &status, 0), child);
    child = -1;
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* After the holder releases, a fresh contender must acquire (via the
     * replacement leaf, which is now the live public namespace). */
    runtime_state_lock_release(parent_lock);
    parent_lock = -1;
    fflush(NULL);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        int child_lock = runtime_state_lock_acquire();
        if (child_lock < 0) _exit(2);
        runtime_state_lock_release(child_lock);
        _exit(0);
    }
    if (child < 0) goto cleanup;
    CHECK_EQ_INT(waitpid(child, &status, 0), child);
    child = -1;
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

cleanup:
    if (parent_lock >= 0) runtime_state_lock_release(parent_lock);
    if (child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
    }
    if (entered[0] >= 0) close(entered[0]);
    if (entered[1] >= 0) close(entered[1]);
    (void)unlink(new_lock);
    (void)rmdir(lock_dir);
    (void)unlink(old_lock);
    (void)rmdir(moved_dir);
    (void)rmdir(runtime);
    if (had_xdg) {
        CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", saved_xdg, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("XDG_RUNTIME_DIR"), 0);
    }
}

static int replace_fd_with_devnull(int target_fd) {
    int replacement = open("/dev/null", O_RDONLY | O_CLOEXEC);

    if (replacement < 0) return -1;
    if (replacement != target_fd) {
        if (dup2(replacement, target_fd) != target_fd) {
            int saved_errno = errno;
            close(replacement);
            errno = saved_errno;
            return -1;
        }
        close(replacement);
        if (fcntl(target_fd, F_SETFD, FD_CLOEXEC) != 0) {
            int saved_errno = errno;
            close(target_fd);
            errno = saved_errno;
            return -1;
        }
    }
    return target_fd;
}

static int replace_fd_with_lock_path(int target_fd, const char *path) {
    int replacement = open(path, O_RDWR | O_CLOEXEC);

    if (replacement < 0) return -1;
    if (replacement != target_fd) {
        if (dup2(replacement, target_fd) != target_fd) {
            int saved_errno = errno;
            close(replacement);
            errno = saved_errno;
            return -1;
        }
        close(replacement);
        if (fcntl(target_fd, F_SETFD, FD_CLOEXEC) != 0) {
            int saved_errno = errno;
            close(target_fd);
            errno = saved_errno;
            return -1;
        }
    }
    return target_fd;
}

static int occupy_fds_through(int target_fd, int *fds, size_t capacity,
                              size_t *count_out) {
    size_t count = 0;

    if (!fds || !count_out || target_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    while (count < capacity) {
        int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);

        if (fd < 0) goto fail;
        if (fd > target_fd) {
            close(fd);
            errno = ERANGE;
            goto fail;
        }
        fds[count++] = fd;
        if (fd == target_fd) {
            *count_out = count;
            return 0;
        }
    }
    errno = EMFILE;

fail: {
        int saved_errno = errno;
        while (count > 0) close(fds[--count]);
        errno = saved_errno;
        return -1;
    }
}

/* Return 0 when a disposable contender acquires, 1 for expected contention,
 * and 2+ for harness/setup failures. */
static int private_lock_child_outcome(const char *directory,
                                      const char *lock_name) {
    pid_t child = fork();
    int status = 0;

    if (child < 0) return 2;
    if (child == 0) {
        int dir_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        int token;

        if (dir_fd < 0) _exit(3);
        token = try_lock_private_file_at(dir_fd, lock_name);
        close(dir_fd);
        if (token >= 0) {
            unlock_private_file(token);
            _exit(0);
        }
        if (errno == EWOULDBLOCK
#if EAGAIN != EWOULDBLOCK
            || errno == EAGAIN
#endif
        ) {
            _exit(1);
        }
        _exit(4);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 5;
    return WEXITSTATUS(status);
}

TEST(private_lock_token_is_anonymous_and_lock_path_rebind_survives_release) {
    char root[] = "/tmp/gs_private_lock_anon_XXXXXX";
    char lock_path[512];
    struct stat token_st;
    struct stat lock_st;
    int dir_fd = -1;
    int token = -1;
    int replacement = -1;

    if (!ts_mkdtemp(root)) { CHECK(!"mkdtemp failed"); return; }
    snprintf(lock_path, sizeof(lock_path), "%s/.test-lock", root);
    dir_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(dir_fd >= 0);
    if (dir_fd < 0) goto cleanup;
    token = lock_private_file_at(dir_fd, ".test-lock");
    CHECK(token >= 0);
    if (token < 0) goto cleanup;
    CHECK_EQ_INT(fstat(token, &token_st), 0);
    CHECK_EQ_INT(stat(lock_path, &lock_st), 0);
    CHECK(token_st.st_dev != lock_st.st_dev || token_st.st_ino != lock_st.st_ino);

    close(token);
    replacement = replace_fd_with_lock_path(token, lock_path);
    CHECK_EQ_INT(replacement, token);
    if (replacement < 0) goto cleanup;
    unlock_private_file(token);
    token = -1;
    CHECK(fcntl(replacement, F_GETFD) >= 0);
    CHECK_EQ_INT(private_lock_child_outcome(root, ".test-lock"), 0);

cleanup:
    if (token >= 0) unlock_private_file(token);
    if (replacement >= 0) close(replacement);
    if (dir_fd >= 0) close(dir_fd);
    (void)unlink(lock_path);
    (void)rmdir(root);
}

/* AR-08 L7: an exposed token is only an opaque handle. Closing it and reusing
 * the integer must not let release close the replacement, but the stale
 * context still has to retire its registry references so nested locks remain
 * live only for their real owners. Double-release is an unknown-token no-op. */
TEST(private_lock_release_identity_checks_reused_and_nested_tokens) {
    char root[] = "/tmp/gs_private_lock_reuse_XXXXXX";
    char lock_path[512];
    int dir_fd = -1;
    int first = -1;
    int second = -1;
    int replacement = -1;
    int double_replacement = -1;

    if (!ts_mkdtemp(root)) { CHECK(!"mkdtemp failed"); return; }
    snprintf(lock_path, sizeof(lock_path), "%s/.test-lock", root);
    dir_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(dir_fd >= 0);
    if (dir_fd < 0) goto cleanup;
    first = lock_private_file_at(dir_fd, ".test-lock");
    second = lock_private_file_at(dir_fd, ".test-lock");
    CHECK(first >= 0);
    CHECK(second >= 0);
    if (first < 0 || second < 0) goto cleanup;

    close(first);
    replacement = replace_fd_with_devnull(first);
    CHECK_EQ_INT(replacement, first);
    if (replacement < 0) goto cleanup;
    errno = ERANGE;
    unlock_private_file(first);
    CHECK_EQ_INT(errno, ERANGE);
    CHECK(fcntl(replacement, F_GETFD) >= 0);
    CHECK_EQ_INT(private_lock_child_outcome(root, ".test-lock"), 1);

    unlock_private_file(second);
    second = -1;
    CHECK_EQ_INT(private_lock_child_outcome(root, ".test-lock"), 0);

    close(replacement);
    replacement = -1;
    double_replacement = replace_fd_with_devnull(first);
    CHECK_EQ_INT(double_replacement, first);
    errno = ENOTTY;
    unlock_private_file(first);
    CHECK_EQ_INT(errno, ENOTTY);
    CHECK(fcntl(double_replacement, F_GETFD) >= 0);

cleanup:
    if (first >= 0 && replacement < 0 && double_replacement < 0) {
        unlock_private_file(first);
    }
    if (second >= 0) unlock_private_file(second);
    if (replacement >= 0) close(replacement);
    if (double_replacement >= 0) close(double_replacement);
    if (dir_fd >= 0) close(dir_fd);
    (void)unlink(lock_path);
    (void)rmdir(root);
}

/* A stale context can share both the numeric descriptor and inode identity of
 * a newer nested token. The older generation must be consumed first without
 * closing or releasing the newer registered lock (the ABA rejected by the
 * independent AR-08 L7 review). */
TEST(private_lock_release_preserves_newer_registered_token_on_aba) {
    char root[] = "/tmp/gs_private_lock_aba_XXXXXX";
    char filler_path[512], target_path[512];
    int occupied[128];
    size_t occupied_count = 0;
    int dir_fd = -1;
    int filler = -1;
    int stale = -1;
    int live = -1;
    bool stale_retired = false;

    for (size_t i = 0; i < sizeof(occupied) / sizeof(occupied[0]); i++) {
        occupied[i] = -1;
    }
    if (!ts_mkdtemp(root)) { CHECK(!"mkdtemp failed"); return; }
    snprintf(filler_path, sizeof(filler_path), "%s/.filler", root);
    snprintf(target_path, sizeof(target_path), "%s/.target", root);
    dir_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(dir_fd >= 0);
    if (dir_fd < 0) goto cleanup;

    filler = lock_private_file_at(dir_fd, ".filler");
    stale = lock_private_file_at(dir_fd, ".target");
    CHECK(filler >= 0);
    CHECK(stale >= 0);
    if (filler < 0 || stale < 0) goto cleanup;
    unlock_private_file(filler);
    filler = -1;
    close(stale);

    CHECK_EQ_INT(occupy_fds_through(
                     stale, occupied,
                     sizeof(occupied) / sizeof(occupied[0]), &occupied_count),
                 0);
    if (occupied_count == 0) goto cleanup;
    CHECK_EQ_INT(occupied[occupied_count - 1], stale);
    close(occupied[occupied_count - 1]);
    occupied[occupied_count - 1] = -1;

    live = lock_private_file_at(dir_fd, ".target");
    CHECK_EQ_INT(live, stale);
    if (live < 0 || live != stale) goto cleanup;

    errno = ENOTTY;
    unlock_private_file(stale);
    stale_retired = true;
    CHECK_EQ_INT(errno, ENOTTY);
    CHECK(fcntl(live, F_GETFD) >= 0);
    CHECK_EQ_INT(private_lock_child_outcome(root, ".target"), 1);

    unlock_private_file(live);
    live = -1;
    CHECK_EQ_INT(private_lock_child_outcome(root, ".target"), 0);

cleanup:
    if (!stale_retired && stale >= 0) unlock_private_file(stale);
    if (live >= 0) unlock_private_file(live);
    if (filler >= 0) unlock_private_file(filler);
    for (size_t i = 0; i < occupied_count; i++) {
        if (occupied[i] >= 0) close(occupied[i]);
    }
    if (dir_fd >= 0) close(dir_fd);
    (void)unlink(filler_path);
    (void)unlink(target_path);
    (void)rmdir(root);
}

/* A runtime-token release must never fall through into the generic registry:
 * a foreign integer could be a live private-lock token in the same process. */
TEST(runtime_lock_release_ignores_foreign_private_token) {
    char root[] = "/tmp/gs_runtime_foreign_token_XXXXXX";
    char lock_path[512];
    int dir_fd = -1;
    int token = -1;

    if (!ts_mkdtemp(root)) { CHECK(!"mkdtemp failed"); return; }
    snprintf(lock_path, sizeof(lock_path), "%s/.test-lock", root);
    dir_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(dir_fd >= 0);
    if (dir_fd < 0) goto cleanup;
    token = lock_private_file_at(dir_fd, ".test-lock");
    CHECK(token >= 0);
    if (token < 0) goto cleanup;

    runtime_state_lock_release(token);
    CHECK(fcntl(token, F_GETFD) >= 0);
    CHECK_EQ_INT(private_lock_child_outcome(root, ".test-lock"), 1);
    unlock_private_file(token);
    token = -1;
    CHECK_EQ_INT(private_lock_child_outcome(root, ".test-lock"), 0);

cleanup:
    if (token >= 0) unlock_private_file(token);
    if (dir_fd >= 0) close(dir_fd);
    (void)unlink(lock_path);
    (void)rmdir(root);
}

static int runtime_lock_child_outcome(void) {
    pid_t child = fork();
    int status = 0;

    if (child < 0) return 2;
    if (child == 0) {
        int token = runtime_state_lock_acquire();
        if (token >= 0) {
            runtime_state_lock_release(token);
            _exit(0);
        }
        if (errno == EWOULDBLOCK
#if EAGAIN != EWOULDBLOCK
            || errno == EAGAIN
#endif
        ) {
            _exit(1);
        }
        _exit(3);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 4;
    return WEXITSTATUS(status);
}

/* Runtime contexts have their own registry layered over private-lock tokens.
 * Reusing a stale runtime token number for a newer nested runtime token must
 * consume the old wrapper/generation first, not hijack the newer lock. */
TEST(runtime_lock_release_preserves_newer_registered_token_on_aba) {
    char runtime[] = "/tmp/gs_runtime_token_aba_XXXXXX";
    char lock_dir[512], lock_path[512];
    char saved_xdg[MAX_PATH_LEN] = "";
    const char *old_xdg = getenv("XDG_RUNTIME_DIR");
    bool had_xdg = old_xdg && *old_xdg;
    int occupied[128];
    size_t occupied_count = 0;
    int filler = -1;
    int stale = -1;
    int live = -1;
    bool stale_retired = false;

    for (size_t i = 0; i < sizeof(occupied) / sizeof(occupied[0]); i++) {
        occupied[i] = -1;
    }
    if (had_xdg) safe_strncpy(saved_xdg, old_xdg, sizeof(saved_xdg));
    if (!ts_mkdtemp(runtime)) { CHECK(!"mkdtemp failed"); return; }
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);

    filler = runtime_state_lock_acquire();
    stale = runtime_state_lock_acquire();
    CHECK(filler >= 0);
    CHECK(stale >= 0);
    if (filler < 0 || stale < 0) goto cleanup;
    runtime_state_lock_release(filler);
    filler = -1;
    close(stale);

    CHECK_EQ_INT(occupy_fds_through(
                     stale, occupied,
                     sizeof(occupied) / sizeof(occupied[0]), &occupied_count),
                 0);
    CHECK(occupied_count >= 3);
    if (occupied_count < 3) goto cleanup;
    CHECK_EQ_INT(occupied[occupied_count - 1], stale);
    close(occupied[0]);
    occupied[0] = -1;
    close(occupied[1]);
    occupied[1] = -1;
    close(occupied[occupied_count - 1]);
    occupied[occupied_count - 1] = -1;

    live = runtime_state_lock_acquire();
    CHECK_EQ_INT(live, stale);
    if (live < 0 || live != stale) goto cleanup;

    runtime_state_lock_release(stale);
    stale_retired = true;
    CHECK(fcntl(live, F_GETFD) >= 0);
    CHECK_EQ_INT(runtime_lock_child_outcome(), 1);

    runtime_state_lock_release(live);
    live = -1;
    CHECK_EQ_INT(runtime_lock_child_outcome(), 0);

cleanup:
    if (!stale_retired && stale >= 0) runtime_state_lock_release(stale);
    if (live >= 0) runtime_state_lock_release(live);
    if (filler >= 0) runtime_state_lock_release(filler);
    for (size_t i = 0; i < occupied_count; i++) {
        if (occupied[i] >= 0) close(occupied[i]);
    }
    snprintf(lock_path, sizeof(lock_path), "%s/gitswitch-runtime/.lock", runtime);
    snprintf(lock_dir, sizeof(lock_dir), "%s/gitswitch-runtime", runtime);
    (void)unlink(lock_path);
    (void)rmdir(lock_dir);
    (void)rmdir(runtime);
    if (had_xdg) {
        CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", saved_xdg, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("XDG_RUNTIME_DIR"), 0);
    }
}

/* The runtime wrapper adds retained namespace descriptors, but its public
 * lock token has the same identity contract as a generic private token. */
TEST(runtime_lock_release_preserves_reused_nested_token) {
    char runtime[] = "/tmp/gs_runtime_token_reuse_XXXXXX";
    char lock_dir[512], lock_path[512];
    char saved_xdg[MAX_PATH_LEN] = "";
    const char *old_xdg = getenv("XDG_RUNTIME_DIR");
    bool had_xdg = old_xdg && *old_xdg;
    int first = -1;
    int second = -1;
    int replacement = -1;

    if (had_xdg) safe_strncpy(saved_xdg, old_xdg, sizeof(saved_xdg));
    if (!ts_mkdtemp(runtime)) { CHECK(!"mkdtemp failed"); return; }
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);
    first = runtime_state_lock_acquire();
    second = runtime_state_lock_acquire();
    CHECK(first >= 0);
    CHECK(second >= 0);
    if (first < 0 || second < 0) goto cleanup;

    close(first);
    replacement = replace_fd_with_devnull(first);
    CHECK_EQ_INT(replacement, first);
    if (replacement < 0) goto cleanup;
    runtime_state_lock_release(first);
    first = -1;
    CHECK(fcntl(replacement, F_GETFD) >= 0);
    CHECK_EQ_INT(runtime_lock_child_outcome(), 1);

    runtime_state_lock_release(second);
    second = -1;
    CHECK_EQ_INT(runtime_lock_child_outcome(), 0);

cleanup:
    if (first >= 0) runtime_state_lock_release(first);
    if (second >= 0) runtime_state_lock_release(second);
    if (replacement >= 0) close(replacement);
    snprintf(lock_path, sizeof(lock_path), "%s/gitswitch-runtime/.lock", runtime);
    snprintf(lock_dir, sizeof(lock_dir), "%s/gitswitch-runtime", runtime);
    (void)unlink(lock_path);
    (void)rmdir(lock_dir);
    (void)rmdir(runtime);
    if (had_xdg) {
        CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", saved_xdg, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("XDG_RUNTIME_DIR"), 0);
    }
}

TEST(runtime_lock_token_is_anonymous_and_lock_path_rebind_survives_release) {
    char runtime[] = "/tmp/gs_runtime_token_anon_XXXXXX";
    char lock_dir[512], lock_path[512];
    char saved_xdg[MAX_PATH_LEN] = "";
    const char *old_xdg = getenv("XDG_RUNTIME_DIR");
    bool had_xdg = old_xdg && *old_xdg;
    struct stat token_st;
    struct stat lock_st;
    int token = -1;
    int replacement = -1;

    if (had_xdg) safe_strncpy(saved_xdg, old_xdg, sizeof(saved_xdg));
    if (!ts_mkdtemp(runtime)) { CHECK(!"mkdtemp failed"); return; }
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);
    snprintf(lock_path, sizeof(lock_path), "%s/gitswitch-runtime/.lock", runtime);
    snprintf(lock_dir, sizeof(lock_dir), "%s/gitswitch-runtime", runtime);
    token = runtime_state_lock_acquire();
    CHECK(token >= 0);
    if (token < 0) goto cleanup;
    CHECK_EQ_INT(fstat(token, &token_st), 0);
    CHECK_EQ_INT(stat(lock_path, &lock_st), 0);
    CHECK(token_st.st_dev != lock_st.st_dev || token_st.st_ino != lock_st.st_ino);

    close(token);
    replacement = replace_fd_with_lock_path(token, lock_path);
    CHECK_EQ_INT(replacement, token);
    if (replacement < 0) goto cleanup;
    runtime_state_lock_release(token);
    token = -1;
    CHECK(fcntl(replacement, F_GETFD) >= 0);
    CHECK_EQ_INT(runtime_lock_child_outcome(), 0);

cleanup:
    if (token >= 0) runtime_state_lock_release(token);
    if (replacement >= 0) close(replacement);
    (void)unlink(lock_path);
    (void)rmdir(lock_dir);
    (void)rmdir(runtime);
    if (had_xdg) {
        CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", saved_xdg, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("XDG_RUNTIME_DIR"), 0);
    }
}

/* Opaque lock tokens inherited across fork may be closed and their numeric fd
 * reused before the child releases them.  Releasing stale bookkeeping must
 * never close the unrelated replacement descriptor. */
TEST(private_lock_release_ignores_reused_inherited_token) {
    char root[] = "/tmp/gs_private_lock_fork_XXXXXX";
    char lock_path[512];
    struct stat token_st;
    struct stat lock_st;
    int dir_fd = -1;
    int token = -1;
    pid_t child = -1;
    int status = 0;

    if (!ts_mkdtemp(root)) { CHECK(!"mkdtemp failed"); return; }
    dir_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(dir_fd >= 0);
    if (dir_fd < 0) goto cleanup;
    token = lock_private_file_at(dir_fd, ".test-lock");
    CHECK(token >= 0);
    if (token < 0) goto cleanup;
    snprintf(lock_path, sizeof(lock_path), "%s/.test-lock", root);
    CHECK_EQ_INT(fstat(token, &token_st), 0);
    CHECK_EQ_INT(stat(lock_path, &lock_st), 0);
    CHECK(token_st.st_dev != lock_st.st_dev || token_st.st_ino != lock_st.st_ino);

    fflush(NULL);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        int replacement;

        close(token);
        replacement = replace_fd_with_lock_path(token, lock_path);
        if (replacement != token) _exit(2);
        unlock_private_file(token);
        _exit(fcntl(token, F_GETFD) >= 0 ? 0 : 3);
    }
    if (child > 0) {
        CHECK_EQ_INT(waitpid(child, &status, 0), child);
        child = -1;
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }

cleanup:
    if (child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
    }
    if (token >= 0) {
        unlock_private_file(token);
        token = -1;
        CHECK_EQ_INT(private_lock_child_outcome(root, ".test-lock"), 0);
    }
    if (dir_fd >= 0) close(dir_fd);
    {
        (void)unlink(lock_path);
    }
    (void)rmdir(root);
}

/* runtime_state_lock keeps additional parent/leaf descriptors internally.
 * A post-fork reset must identity-check those numbers too: the child can close
 * and reuse every inherited fd before its first runtime-lock API call. */
TEST(runtime_lock_fork_reset_preserves_reused_descriptor_numbers) {
    char runtime[] = "/tmp/gs_runtime_fdreuse_XXXXXX";
    char lock_dir[512], lock_path[512];
    char saved_xdg[MAX_PATH_LEN] = "";
    const char *old_xdg = getenv("XDG_RUNTIME_DIR");
    bool had_xdg = old_xdg && *old_xdg;
    int parent_lock = -1;
    pid_t child = -1;
    int status = 0;
    struct stat token_st;
    struct stat lock_st;

    if (had_xdg) safe_strncpy(saved_xdg, old_xdg, sizeof(saved_xdg));
    if (!ts_mkdtemp(runtime)) { CHECK(!"mkdtemp failed"); return; }
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);
    parent_lock = runtime_state_lock_acquire();
    CHECK(parent_lock >= 3);
    if (parent_lock < 3) goto cleanup;
    snprintf(lock_path, sizeof(lock_path), "%s/gitswitch-runtime/.lock", runtime);
    snprintf(lock_dir, sizeof(lock_dir), "%s/gitswitch-runtime", runtime);
    CHECK_EQ_INT(fstat(parent_lock, &token_st), 0);
    CHECK_EQ_INT(stat(lock_path, &lock_st), 0);
    CHECK(token_st.st_dev != lock_st.st_dev || token_st.st_ino != lock_st.st_ino);

    fflush(NULL);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        int replacements[256];
        int count = 0;

        for (int fd = 3; fd <= parent_lock; fd++) close(fd);
        while (count < (int)(sizeof(replacements) / sizeof(replacements[0])) &&
               count + 3 < parent_lock) {
            int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
            if (fd < 0) _exit(2);
            if (fd != count + 3) _exit(3);
            replacements[count++] = fd;
        }
        replacements[count] = replace_fd_with_lock_path(parent_lock,
                                                        lock_path);
        if (replacements[count] != parent_lock) _exit(4);
        count++;
        runtime_state_lock_release(parent_lock);
        for (int i = 0; i < count; i++) {
            if (fcntl(replacements[i], F_GETFD) < 0) _exit(5);
        }
        _exit(0);
    }
    if (child > 0) {
        CHECK_EQ_INT(waitpid(child, &status, 0), child);
        child = -1;
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }

cleanup:
    if (child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
    }
    if (parent_lock >= 0) {
        runtime_state_lock_release(parent_lock);
        parent_lock = -1;
        CHECK_EQ_INT(runtime_lock_child_outcome(), 0);
    }
    (void)unlink(lock_path);
    (void)rmdir(lock_dir);
    (void)rmdir(runtime);
    if (had_xdg) {
        CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", saved_xdg, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("XDG_RUNTIME_DIR"), 0);
    }
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

/* AR-06 F74: a symlink living in a trusted PATH directory can point at a 0755
 * binary that sits inside a group/world-writable directory, where an attacker
 * atomically swaps the target. The candidate stat() followed the link and only
 * vetted the target file's own mode, so the shadow resolved. find_command_path
 * must canonicalize and reject when the directory holding the resolved target
 * is itself writable — while still honoring a symlink into a trusted dir. */
TEST(find_command_path_rejects_symlink_into_writable_dir) {
    char linkdir[256], wwdir[256], okdir[256];
    char realtool[512], oktool[512];
    char wwmarker[512], okmarker[512];
    char evil_link[600], good_link[600];
    char buf[512], path[512];

    if (make_test_dir(linkdir, sizeof(linkdir), 0755) != 0 ||
        make_test_dir(wwdir, sizeof(wwdir), 0777) != 0 ||
        make_test_dir(okdir, sizeof(okdir), 0755) != 0) {
        CHECK(!"mkdtemp failed");
        return;
    }

    /* Real 0755 targets: one inside the world-writable dir, one inside a
     * trusted dir. The files themselves are identical and un-writable. */
    snprintf(wwmarker, sizeof(wwmarker), "%s/marker", wwdir);
    snprintf(okmarker, sizeof(okmarker), "%s/marker", okdir);
    CHECK_EQ_INT(install_fake_tool(wwdir, "gs_f74_real", wwmarker,
                                   realtool, sizeof(realtool)), 0);
    CHECK_EQ_INT(install_fake_tool(okdir, "gs_f74_real", okmarker,
                                   oktool, sizeof(oktool)), 0);

    /* Both symlinks live in the trusted linkdir. */
    snprintf(evil_link, sizeof(evil_link), "%s/gs_f74_evil", linkdir);
    snprintf(good_link, sizeof(good_link), "%s/gs_f74_good", linkdir);
    CHECK_EQ_INT(symlink(realtool, evil_link), 0);
    CHECK_EQ_INT(symlink(oktool, good_link), 0);

    save_path();
    snprintf(path, sizeof(path), "%s", linkdir);
    setenv("PATH", path, 1);

    /* Shadow: link's own dir is trusted, but the resolved target's dir is
     * world-writable — must be refused, both by name and by explicit path. */
    CHECK_EQ_INT(find_command_path("gs_f74_evil", buf, sizeof(buf)), -1);
    CHECK_EQ_INT(find_command_path(evil_link, buf, sizeof(buf)), -1);

    /* Control: link into a trusted dir still resolves. */
    CHECK_EQ_INT(find_command_path("gs_f74_good", buf, sizeof(buf)), 0);

    restore_path();
    unlink(evil_link);
    unlink(good_link);
    remove_test_dir(wwdir, realtool, wwmarker);
    remove_test_dir(okdir, oktool, okmarker);
    rmdir(linkdir);
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
    RUN_TEST(ssh_add_key_low_level_contract_is_one_unvalidated_argv);
    RUN_TEST(find_command_path_rejects_metachars);
    RUN_TEST(find_command_path_finds_real_binary);
    RUN_TEST(command_exists_basic);
    RUN_TEST(file_helpers_apply_descriptor_permissions);
    RUN_TEST(ensure_private_dir_contract_matches_adoption_policy);
    RUN_TEST(create_directory_recursive_validates_every_component_and_symlink_policy);
    RUN_TEST(create_directory_recursive_detects_ancestor_replacement);
    RUN_TEST(runtime_state_lock_excludes_shared_xdg_writers_fail_fast);
    RUN_TEST(runtime_state_lock_rejects_unsafe_xdg_runtime_dir);
    RUN_TEST(runtime_entry_replacement_classification_is_lifetime_safe);
    RUN_TEST(runtime_state_lock_excludes_contender_after_ancestor_replacement);
    RUN_TEST(runtime_state_lock_rejects_namespace_replacement_while_waiting);
    RUN_TEST(runtime_state_lock_excludes_contender_after_leaf_replacement);
    RUN_TEST(private_lock_token_is_anonymous_and_lock_path_rebind_survives_release);
    RUN_TEST(private_lock_release_identity_checks_reused_and_nested_tokens);
    RUN_TEST(private_lock_release_preserves_newer_registered_token_on_aba);
    RUN_TEST(runtime_lock_release_ignores_foreign_private_token);
    RUN_TEST(runtime_lock_release_preserves_newer_registered_token_on_aba);
    RUN_TEST(runtime_lock_release_preserves_reused_nested_token);
    RUN_TEST(runtime_lock_token_is_anonymous_and_lock_path_rebind_survives_release);
    RUN_TEST(private_lock_release_ignores_reused_inherited_token);
    RUN_TEST(runtime_lock_fork_reset_preserves_reused_descriptor_numbers);
    RUN_TEST(find_command_path_skips_world_writable_dir);
    RUN_TEST(find_command_path_rejects_group_writable_components);
    RUN_TEST(find_command_path_rejects_symlink_into_writable_dir);
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
