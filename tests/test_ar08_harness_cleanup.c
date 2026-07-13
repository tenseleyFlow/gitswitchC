#define _GNU_SOURCE
#include "test.h"

#include <stdbool.h>
#include <fcntl.h>

static char g_child_path[4096];
static char g_moved_path[4096];
static char g_foreign_path[4096];
static int g_replace_result;
static int g_getcwd_calls;
static int g_chdir_calls;

static int create_marker(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    ssize_t written = write(fd, "x", 1);
    int saved_errno = written == 1 ? 0 : (written < 0 ? errno : EIO);
    if (close(fd) != 0 && saved_errno == 0) saved_errno = errno;
    if (saved_errno != 0) {
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static bool path_is_present(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0;
}

static void replace_child_with_foreign_symlink(void) {
    if (g_replace_result != -1) return;
    g_replace_result =
        rename(g_child_path, g_moved_path) == 0 &&
                symlink(g_foreign_path, g_child_path) == 0
            ? 0
            : errno;
}

static char *fail_second_getcwd(char *buffer, size_t size) {
    g_getcwd_calls++;
    if (g_getcwd_calls == 2) {
        errno = EIO;
        return NULL;
    }
    return getcwd(buffer, size);
}

static int fail_second_chdir(const char *path) {
    g_chdir_calls++;
    if (g_chdir_calls == 2) {
        errno = EPERM;
        return -1;
    }
    return chdir(path);
}

TEST(tracked_root_replacement_never_traverses_foreign_target) {
    char root[] = "/tmp/gitswitch-ar08-harness-root-XXXXXX";
    char foreign[] = "/tmp/gitswitch-ar08-harness-foreign-XXXXXX";
    char moved[4096], owned[4096], moved_owned[4096], sentinel[4096];

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK(mkdtemp(foreign) != NULL);
    CHECK((size_t)snprintf(moved, sizeof(moved), "%s.moved", root) <
          sizeof(moved));
    CHECK((size_t)snprintf(owned, sizeof(owned), "%s/owned", root) <
          sizeof(owned));
    CHECK((size_t)snprintf(moved_owned, sizeof(moved_owned), "%s/owned",
                           moved) < sizeof(moved_owned));
    CHECK((size_t)snprintf(sentinel, sizeof(sentinel), "%s/sentinel",
                           foreign) < sizeof(sentinel));
    CHECK_EQ_INT(create_marker(owned), 0);
    CHECK_EQ_INT(create_marker(sentinel), 0);
    CHECK_EQ_INT(rename(root, moved), 0);
    CHECK_EQ_INT(symlink(foreign, root), 0);

    ts_cleanup_tmpdirs();

    CHECK(path_is_present(sentinel));
    CHECK(!path_is_present(moved_owned));

    (void)unlink(root);
    (void)unlink(moved_owned);
    (void)rmdir(moved);
    (void)unlink(sentinel);
    (void)rmdir(foreign);
}

TEST(child_replacement_between_classification_and_descent_is_contained) {
    char root[] = "/tmp/gitswitch-ar08-harness-child-XXXXXX";
    char foreign[] = "/tmp/gitswitch-ar08-harness-victim-XXXXXX";
    char owned[4096], moved_owned[4096], sentinel[4096];

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK(mkdtemp(foreign) != NULL);
    CHECK((size_t)snprintf(g_child_path, sizeof(g_child_path), "%s/child",
                           root) < sizeof(g_child_path));
    CHECK((size_t)snprintf(g_moved_path, sizeof(g_moved_path), "%s.moved",
                           root) < sizeof(g_moved_path));
    CHECK((size_t)snprintf(g_foreign_path, sizeof(g_foreign_path), "%s",
                           foreign) < sizeof(g_foreign_path));
    CHECK((size_t)snprintf(owned, sizeof(owned), "%s/owned", g_child_path) <
          sizeof(owned));
    CHECK((size_t)snprintf(moved_owned, sizeof(moved_owned), "%s/owned",
                           g_moved_path) < sizeof(moved_owned));
    CHECK((size_t)snprintf(sentinel, sizeof(sentinel), "%s/sentinel",
                           foreign) < sizeof(sentinel));
    CHECK_EQ_INT(mkdir(g_child_path, 0700), 0);
    CHECK_EQ_INT(create_marker(owned), 0);
    CHECK_EQ_INT(create_marker(sentinel), 0);

    g_replace_result = -1;
    ts_set_cleanup_pre_descend_hook(replace_child_with_foreign_symlink);
    ts_cleanup_tmpdirs();
    ts_set_cleanup_pre_descend_hook(NULL);

    CHECK_EQ_INT(g_replace_result, 0);
    CHECK(path_is_present(sentinel));
    CHECK(!path_is_present(moved_owned));

    (void)unlink(g_child_path);
    (void)rmdir(root);
    (void)unlink(moved_owned);
    (void)rmdir(g_moved_path);
    (void)unlink(sentinel);
    (void)rmdir(foreign);
}

TEST(normal_cleanup_removes_nested_fixture_without_residue) {
    char root[] = "/tmp/gitswitch-ar08-harness-normal-XXXXXX";
    char child[4096], marker[4096], link_path[4096];

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK((size_t)snprintf(child, sizeof(child), "%s/a/b", root) <
          sizeof(child));
    CHECK((size_t)snprintf(marker, sizeof(marker), "%s/marker", child) <
          sizeof(marker));
    CHECK((size_t)snprintf(link_path, sizeof(link_path), "%s/link", child) <
          sizeof(link_path));
    char parent[4096];
    CHECK((size_t)snprintf(parent, sizeof(parent), "%s/a", root) <
          sizeof(parent));
    CHECK_EQ_INT(mkdir(parent, 0700), 0);
    CHECK_EQ_INT(mkdir(child, 0700), 0);
    CHECK_EQ_INT(create_marker(marker), 0);
    CHECK_EQ_INT(symlink("marker", link_path), 0);

    ts_cleanup_tmpdirs();

    CHECK(!path_is_present(root));
}

TEST(trusted_fixture_reports_restore_chdir_failure) {
    char home[] = "/tmp/gitswitch-ar08-harness-home-XXXXXX";
    char original_cwd[4096], path[4096];
    char *saved_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
    bool had_home = getenv("HOME") != NULL;

    CHECK(getcwd(original_cwd, sizeof(original_cwd)) != NULL);
    CHECK(mkdtemp(home) != NULL);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    g_getcwd_calls = 0;
    g_chdir_calls = 0;
    ts_set_trusted_cwd_hooks(fail_second_getcwd, fail_second_chdir);
    errno = 0;
    CHECK(ts_mkdtemp_trusted(path, sizeof(path), "restore-failure") == NULL);
    int observed_errno = errno;
    ts_set_trusted_cwd_hooks(NULL, NULL);

    CHECK_EQ_INT(g_getcwd_calls, 2);
    CHECK_EQ_INT(g_chdir_calls, 2);
    CHECK_EQ_INT(observed_errno, EPERM);
    CHECK_EQ_INT(chdir(original_cwd), 0);
    if (had_home) {
        CHECK(saved_home != NULL);
        if (saved_home) CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("HOME"), 0);
    }
    free(saved_home);
    CHECK_EQ_INT(rmdir(home), 0);
}

TEST_MAIN_BEGIN()
    RUN_TEST(tracked_root_replacement_never_traverses_foreign_target);
    RUN_TEST(child_replacement_between_classification_and_descent_is_contained);
    RUN_TEST(normal_cleanup_removes_nested_fixture_without_residue);
    RUN_TEST(trusted_fixture_reports_restore_chdir_failure);
TEST_MAIN_END()
