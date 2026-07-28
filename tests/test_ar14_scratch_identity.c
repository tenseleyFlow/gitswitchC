#include "test.h"

#include <sys/wait.h>

#include "signals.h"

static int create_scratch(char *path, size_t path_size,
                          const char *root, const char *name,
                          struct stat *identity) {
    int written = snprintf(path, path_size, "%s/%s", root, name);
    int fd;

    if (written < 0 || (size_t)written >= path_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) return -1;
    if (fstat(fd, identity) != 0) {
        int saved_errno = errno;

        close(fd);
        unlink(path);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

TEST(identity_cleanup_deletes_the_exact_inode_and_preserves_errno) {
    char root[] = "/tmp/gitswitch-ar14-scratch.XXXXXX";
    char path[256];
    struct stat identity;
    char *created;
    int root_fd;
    int fd;

    created = ts_mkdtemp(root);
    CHECK(created != NULL);
    if (!created) return;
    fd = create_scratch(path, sizeof(path), root, "exact", &identity);
    CHECK(fd >= 0);
    if (fd < 0) return;
    CHECK_EQ_INT(close(fd), 0);
    CHECK_EQ_INT(signals_scratch_register_identity(path, &identity), 0);

    /* Generic cleanup must never perform the identity proof/unlink pair. */
    errno = EDOM;
    signals_scratch_cleanup();
    CHECK_EQ_INT(errno, EDOM);
    CHECK_EQ_INT(access(path, F_OK), 0);

    root_fd = open(root, O_RDONLY | O_DIRECTORY);
    CHECK(root_fd >= 0);
    if (root_fd < 0) return;
    errno = EDOM;
    CHECK_EQ_INT(signals_scratch_cleanup_identities_at(root_fd, root), 0);
    CHECK_EQ_INT(errno, EDOM);
    CHECK_EQ_INT(close(root_fd), 0);
    CHECK_EQ_INT(access(path, F_OK), -1);
    CHECK_EQ_INT(errno, ENOENT);
}

TEST(substituted_inode_survives_and_retires_the_stale_slot) {
    char root[] = "/tmp/gitswitch-ar14-substitute.XXXXXX";
    char path[256];
    struct stat original;
    struct stat replacement;
    char *created;
    int original_fd;
    int replacement_fd;

    created = ts_mkdtemp(root);
    CHECK(created != NULL);
    if (!created) return;
    original_fd = create_scratch(path, sizeof(path), root, "scratch",
                                 &original);
    CHECK(original_fd >= 0);
    if (original_fd < 0) return;
    CHECK_EQ_INT(signals_scratch_register_identity(path, &original), 0);
    /* A legacy retry is idempotent but must not downgrade identity cleanup. */
    CHECK_EQ_INT(signals_scratch_register(path), 0);
    CHECK_EQ_INT(unlink(path), 0);

    replacement_fd = create_scratch(path, sizeof(path), root, "scratch",
                                    &replacement);
    CHECK(replacement_fd >= 0);
    if (replacement_fd < 0) {
        close(original_fd);
        return;
    }
    CHECK(!ts_same_identity(&original, &replacement));

    signals_scratch_cleanup();
    CHECK_EQ_INT(access(path, F_OK), 0);
    /* Successful registration of the replacement proves mismatch cleanup
     * cleared the stale identity slot instead of retaining a collision. */
    CHECK_EQ_INT(signals_scratch_register_identity(path, &replacement), 0);
    signals_scratch_unregister(path);

    CHECK_EQ_INT(close(replacement_fd), 0);
    CHECK_EQ_INT(close(original_fd), 0);
    CHECK_EQ_INT(unlink(path), 0);
}

TEST(unlink_failure_retains_identity_for_cleanup_retry) {
    char root[] = "/tmp/gitswitch-ar14-retry.XXXXXX";
    char path[256];
    struct stat identity;
    char *created;
    int root_fd;
    int fd;

    created = ts_mkdtemp(root);
    CHECK(created != NULL);
    if (!created) return;
    fd = create_scratch(path, sizeof(path), root, "retry", &identity);
    CHECK(fd >= 0);
    if (fd < 0) return;
    CHECK_EQ_INT(close(fd), 0);
    CHECK_EQ_INT(signals_scratch_register_identity(path, &identity), 0);
    root_fd = open(root, O_RDONLY | O_DIRECTORY);
    CHECK(root_fd >= 0);
    if (root_fd < 0) return;

    signals_test_fail_scratch_unlink(EACCES);
    errno = ERANGE;
    CHECK_EQ_INT(signals_scratch_cleanup_identities_at(root_fd, root), -1);
    CHECK_EQ_INT(errno, EACCES);
    CHECK_EQ_INT(access(path, F_OK), 0);

    errno = ERANGE;
    CHECK_EQ_INT(signals_scratch_cleanup_identities_at(root_fd, root), 0);
    CHECK_EQ_INT(errno, ERANGE);
    CHECK_EQ_INT(close(root_fd), 0);
    CHECK_EQ_INT(access(path, F_OK), -1);
    CHECK_EQ_INT(errno, ENOENT);
}

TEST(identity_cleanup_is_scoped_to_direct_children) {
    char root[] = "/tmp/gitswitch-ar14-scope.XXXXXX";
    char nested[256];
    char path[256];
    struct stat identity;
    char *created;
    int root_fd;
    int nested_fd;
    int fd;

    created = ts_mkdtemp(root);
    CHECK(created != NULL);
    if (!created) return;
    CHECK(snprintf(nested, sizeof(nested), "%s/nested", root) > 0);
    CHECK_EQ_INT(mkdir(nested, 0700), 0);
    fd = create_scratch(path, sizeof(path), nested, "identity", &identity);
    CHECK(fd >= 0);
    if (fd < 0) return;
    CHECK_EQ_INT(close(fd), 0);
    CHECK_EQ_INT(signals_scratch_register_identity(path, &identity), 0);

    root_fd = open(root, O_RDONLY | O_DIRECTORY);
    CHECK(root_fd >= 0);
    if (root_fd < 0) return;
    CHECK_EQ_INT(signals_scratch_cleanup_identities_at(root_fd, root), 0);
    CHECK_EQ_INT(close(root_fd), 0);
    CHECK_EQ_INT(access(path, F_OK), 0);

    nested_fd = open(nested, O_RDONLY | O_DIRECTORY);
    CHECK(nested_fd >= 0);
    if (nested_fd < 0) return;
    CHECK_EQ_INT(
        signals_scratch_cleanup_identities_at(nested_fd, nested), 0);
    CHECK_EQ_INT(close(nested_fd), 0);
    CHECK_EQ_INT(access(path, F_OK), -1);
    CHECK_EQ_INT(errno, ENOENT);
}

TEST(identity_cleanup_rejects_a_mismatched_directory_descriptor) {
    char root[] = "/tmp/gitswitch-ar14-dir-pair.XXXXXX";
    char other[] = "/tmp/gitswitch-ar14-dir-other.XXXXXX";
    char path[256];
    struct stat identity;
    char *created_other;
    char *created_root;
    int other_fd;
    int root_fd;
    int fd;

    created_root = ts_mkdtemp(root);
    created_other = ts_mkdtemp(other);
    CHECK(created_root != NULL);
    CHECK(created_other != NULL);
    if (!created_root || !created_other) return;
    fd = create_scratch(path, sizeof(path), root, "identity", &identity);
    CHECK(fd >= 0);
    if (fd < 0) return;
    CHECK_EQ_INT(close(fd), 0);
    CHECK_EQ_INT(signals_scratch_register_identity(path, &identity), 0);

    other_fd = open(other, O_RDONLY | O_DIRECTORY);
    CHECK(other_fd >= 0);
    if (other_fd < 0) return;
    errno = 0;
    CHECK_EQ_INT(signals_scratch_cleanup_identities_at(other_fd, root), -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK_EQ_INT(close(other_fd), 0);
    CHECK_EQ_INT(access(path, F_OK), 0);

    root_fd = open(root, O_RDONLY | O_DIRECTORY);
    CHECK(root_fd >= 0);
    if (root_fd < 0) return;
    CHECK_EQ_INT(signals_scratch_cleanup_identities_at(root_fd, root), 0);
    CHECK_EQ_INT(close(root_fd), 0);
    errno = 0;
    CHECK(access(path, F_OK) != 0 && errno == ENOENT);
}

TEST(identity_cleanup_retains_a_new_hardlink_generation_shape) {
    char root[] = "/tmp/gitswitch-ar14-hardlink.XXXXXX";
    char path[256];
    char alias[256];
    struct stat identity;
    char *created;
    int root_fd;
    int fd;

    created = ts_mkdtemp(root);
    CHECK(created != NULL);
    if (!created) return;
    fd = create_scratch(path, sizeof(path), root, "identity", &identity);
    CHECK(fd >= 0);
    if (fd < 0) return;
    CHECK_EQ_INT(close(fd), 0);
    CHECK(snprintf(alias, sizeof(alias), "%s/alias", root) > 0);
    CHECK_EQ_INT(signals_scratch_register_identity(path, &identity), 0);
    CHECK_EQ_INT(link(path, alias), 0);

    root_fd = open(root, O_RDONLY | O_DIRECTORY);
    CHECK(root_fd >= 0);
    if (root_fd < 0) return;
    errno = 0;
    CHECK_EQ_INT(signals_scratch_cleanup_identities_at(root_fd, root), -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK_EQ_INT(access(path, F_OK), 0);
    CHECK_EQ_INT(access(alias, F_OK), 0);

    CHECK_EQ_INT(unlink(alias), 0);
    CHECK_EQ_INT(signals_scratch_cleanup_identities_at(root_fd, root), 0);
    CHECK_EQ_INT(close(root_fd), 0);
    errno = 0;
    CHECK(access(path, F_OK) != 0 && errno == ENOENT);
}

TEST(second_signal_never_unlinks_identity_bound_scratch) {
    char root[] = "/tmp/gitswitch-ar14-signal.XXXXXX";
    char path[256];
    struct stat identity;
    char *created;
    int fd;
    int status = 0;
    pid_t child;

    created = ts_mkdtemp(root);
    CHECK(created != NULL);
    if (!created) return;
    fd = create_scratch(path, sizeof(path), root, "identity", &identity);
    CHECK(fd >= 0);
    if (fd < 0) return;
    CHECK_EQ_INT(close(fd), 0);

    fflush(NULL);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (signals_scratch_register_identity(path, &identity) != 0 ||
            signals_guard_begin() != 0 ||
            raise(SIGTERM) != 0 || !signals_pending()) {
            _exit(10);
        }
        (void)raise(SIGTERM);
        _exit(11);
    }
    if (child < 0) return;

    CHECK_EQ_INT(waitpid(child, &status, 0), child);
    CHECK(WIFSIGNALED(status));
    if (WIFSIGNALED(status)) {
        CHECK_EQ_INT(WTERMSIG(status), SIGTERM);
    }
    CHECK_EQ_INT(access(path, F_OK), 0);
    CHECK_EQ_INT(unlink(path), 0);
}

TEST(identity_registration_rejects_path_and_identity_collisions) {
    char root[] = "/tmp/gitswitch-ar14-collision.XXXXXX";
    char path[256];
    struct stat identity;
    struct stat different;
    char *created;
    int root_fd;
    int fd;

    created = ts_mkdtemp(root);
    CHECK(created != NULL);
    if (!created) return;
    fd = create_scratch(path, sizeof(path), root, "collision", &identity);
    CHECK(fd >= 0);
    if (fd < 0) return;
    CHECK_EQ_INT(close(fd), 0);
    different = identity;
    different.st_ino = identity.st_ino == 0 ? 1 : identity.st_ino - 1;

    CHECK_EQ_INT(signals_scratch_register_identity(path, &identity), 0);
    CHECK_EQ_INT(signals_scratch_register_identity(path, &identity), 0);
    CHECK_EQ_INT(signals_scratch_register_identity(path, &different), -1);
    signals_scratch_unregister(path);

    CHECK_EQ_INT(signals_scratch_register(path), 0);
    CHECK_EQ_INT(signals_scratch_register_identity(path, &identity), 0);
    /* Generic/emergency cleanup must no longer treat the upgraded slot as
     * path-only authority. */
    signals_scratch_cleanup();
    CHECK_EQ_INT(access(path, F_OK), 0);
    root_fd = open(root, O_RDONLY | O_DIRECTORY);
    CHECK(root_fd >= 0);
    if (root_fd >= 0) {
        CHECK_EQ_INT(
            signals_scratch_cleanup_identities_at(root_fd, root), 0);
        CHECK_EQ_INT(close(root_fd), 0);
    }
    errno = 0;
    CHECK(access(path, F_OK) != 0 && errno == ENOENT);
}

TEST_MAIN_BEGIN()
    RUN_TEST(identity_cleanup_deletes_the_exact_inode_and_preserves_errno);
    RUN_TEST(substituted_inode_survives_and_retires_the_stale_slot);
    RUN_TEST(unlink_failure_retains_identity_for_cleanup_retry);
    RUN_TEST(identity_cleanup_is_scoped_to_direct_children);
    RUN_TEST(identity_cleanup_rejects_a_mismatched_directory_descriptor);
    RUN_TEST(identity_cleanup_retains_a_new_hardlink_generation_shape);
    RUN_TEST(second_signal_never_unlinks_identity_bound_scratch);
    RUN_TEST(identity_registration_rejects_path_and_identity_collisions);
TEST_MAIN_END()
