/* AR-11 M18: retirement completion is a fixed, generation-matched
 * certificate. The canonical incomplete record is never deleted by clear();
 * every pre-commit failure remains blocked, while post-publication lost
 * acknowledgements classify an exact pair as committed. */
#include "test.h"

#include "config.h"
#include "error.h"

#include <stdint.h>

#define GUARD_MAX_BYTES 8192U
#define GUARD_NAME ".retirement-incomplete"
#define COMPLETE_NAME ".retirement-complete"
#define STAGE_NAME ".retirement-transition"
#define LOCK_NAME ".retirement.lock"

typedef enum {
    RETIREMENT_GUARD_CLEAR_BEFORE_STAGE_CREATE = 0,
    RETIREMENT_GUARD_CLEAR_AFTER_STAGE_WRITE,
    RETIREMENT_GUARD_CLEAR_BEFORE_FILE_SYNC,
    RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH,
    RETIREMENT_GUARD_CLEAR_AFTER_PUBLISH,
    RETIREMENT_GUARD_CLEAR_BEFORE_DIR_SYNC,
    RETIREMENT_GUARD_CLEAR_AFTER_DIR_SYNC,
    RETIREMENT_GUARD_PAIR_AFTER_MARKER_READ,
    RETIREMENT_GUARD_INSTALL_BEFORE_DIR_SYNC
} retirement_guard_clear_test_stage_t;
typedef int (*retirement_guard_clear_test_hook_fn)(
    retirement_guard_clear_test_stage_t stage, int descriptor,
    const char *marker_name);
retirement_guard_clear_test_hook_fn
gitswitch_test_set_retirement_guard_clear_hook(
    retirement_guard_clear_test_hook_fn hook);

typedef struct {
    config_retirement_guard_t *guard;
    config_retirement_owner_t owner;
    char directory[128];
    char config_path[256];
    char marker_path[256];
    char completion_path[256];
    char stage_path[256];
    char lock_path[256];
    unsigned char marker_data[GUARD_MAX_BYTES];
    size_t marker_length;
    struct stat marker_identity;
} guard_fixture_t;

static int guard_write_all(int fd, const unsigned char *data, size_t length) {
    size_t total = 0U;

    while (total < length) {
        ssize_t count = write(fd, data + total, length - total);

        if (count > 0) {
            total += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static size_t guard_read_file(const char *path, unsigned char *data,
                              size_t capacity) {
    struct stat st;
    size_t total = 0U;
    int fd;

    if (!path || !data || stat(path, &st) != 0 || st.st_size <= 0 ||
        (uintmax_t)st.st_size > capacity) {
        return 0U;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0U;
    while (total < (size_t)st.st_size) {
        ssize_t count = read(fd, data + total, (size_t)st.st_size - total);

        if (count > 0) {
            total += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            total = 0U;
            break;
        }
    }
    if (close(fd) != 0) return 0U;
    return total;
}

static bool guard_files_equal(const char *left, const char *right) {
    unsigned char left_data[GUARD_MAX_BYTES];
    unsigned char right_data[GUARD_MAX_BYTES];
    size_t left_length = guard_read_file(
        left, left_data, sizeof(left_data));
    size_t right_length = guard_read_file(
        right, right_data, sizeof(right_data));

    return left_length > 0U && left_length == right_length &&
           memcmp(left_data, right_data, left_length) == 0;
}

static int guard_atomic_replace_at(
    int directory_fd, const char *destination,
    const unsigned char *data, size_t length) {
    static const char temp_name[] = ".retirement-test-replacement";
    int fd;

    (void)unlinkat(directory_fd, temp_name, 0);
    fd = openat(directory_fd, temp_name,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                0600);
    if (fd < 0 ||
        guard_write_all(fd, data, length) != 0 ||
        fsync(fd) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    if (close(fd) != 0 ||
        renameat(directory_fd, temp_name,
                 directory_fd, destination) != 0 ||
        fsync(directory_fd) != 0) {
        return -1;
    }
    return 0;
}

static bool guard_mutate_token(
    const unsigned char *source, size_t length,
    unsigned char mutated[GUARD_MAX_BYTES]) {
    static const char token_prefix[] = "token=";
    unsigned char *token;

    if (!source || length == 0U || length > GUARD_MAX_BYTES) return false;
    memcpy(mutated, source, length);
    token = memmem(mutated, length, token_prefix,
                   sizeof(token_prefix) - 1U);
    if (!token ||
        (size_t)(token - mutated) + sizeof(token_prefix) - 1U >= length) {
        return false;
    }
    token += sizeof(token_prefix) - 1U;
    *token = *token == (unsigned char)'A'
                 ? (unsigned char)'B'
                 : (unsigned char)'A';
    return true;
}

static int guard_count_retirement_entries(
    const char *directory, int *unexpected) {
    DIR *stream;
    struct dirent *entry;
    int count = 0;
    int bad = 0;

    if (!directory || !unexpected) return -1;
    stream = opendir(directory);
    if (!stream) return -1;
    while ((entry = readdir(stream)) != NULL) {
        if (strncmp(entry->d_name, ".retirement", 11U) != 0) continue;
        count++;
        if (strcmp(entry->d_name, GUARD_NAME) != 0 &&
            strcmp(entry->d_name, COMPLETE_NAME) != 0 &&
            strcmp(entry->d_name, STAGE_NAME) != 0 &&
            strcmp(entry->d_name, LOCK_NAME) != 0) {
            bad++;
        }
    }
    if (closedir(stream) != 0) return -1;
    *unexpected = bad;
    return count;
}

static int guard_fixture_init(guard_fixture_t *fixture) {
    static const char incarnation[] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    if (!fixture) return -1;
    memset(fixture, 0, sizeof(*fixture));
    fixture->owner.account_id = UINT32_C(1);
    memcpy(fixture->owner.account_incarnation, incarnation,
           sizeof(incarnation));
    if ((size_t)snprintf(fixture->directory, sizeof(fixture->directory),
                         "/tmp/gswguardclear.XXXXXX") >=
            sizeof(fixture->directory) ||
        !ts_mkdtemp(fixture->directory) ||
        (size_t)snprintf(fixture->config_path,
                         sizeof(fixture->config_path),
                         "%s/accounts.toml", fixture->directory) >=
            sizeof(fixture->config_path) ||
        (size_t)snprintf(fixture->marker_path,
                         sizeof(fixture->marker_path), "%s/%s",
                         fixture->directory, GUARD_NAME) >=
            sizeof(fixture->marker_path) ||
        (size_t)snprintf(fixture->completion_path,
                         sizeof(fixture->completion_path), "%s/%s",
                         fixture->directory, COMPLETE_NAME) >=
            sizeof(fixture->completion_path) ||
        (size_t)snprintf(fixture->stage_path,
                         sizeof(fixture->stage_path), "%s/%s",
                         fixture->directory, STAGE_NAME) >=
            sizeof(fixture->stage_path) ||
        (size_t)snprintf(fixture->lock_path,
                         sizeof(fixture->lock_path), "%s/%s",
                         fixture->directory, LOCK_NAME) >=
            sizeof(fixture->lock_path) ||
        config_retirement_guard_install_or_adopt(
            fixture->config_path, CONFIG_RETIREMENT_RESET,
            &fixture->owner, 1U, &fixture->guard) != 0) {
        return -1;
    }
    fixture->marker_length = guard_read_file(
        fixture->marker_path, fixture->marker_data,
        sizeof(fixture->marker_data));
    if (fixture->marker_length == 0U ||
        stat(fixture->marker_path, &fixture->marker_identity) != 0) {
        return -1;
    }
    return 0;
}

static void guard_fixture_cleanup(guard_fixture_t *fixture) {
    if (!fixture) return;
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    config_retirement_guard_abandon(&fixture->guard);
    (void)unlink(fixture->marker_path);
    (void)unlink(fixture->completion_path);
    (void)unlink(fixture->stage_path);
    (void)unlink(fixture->lock_path);
    (void)rmdir(fixture->directory);
}

typedef enum {
    HOOK_FAIL = 0,
    HOOK_SYNC_THEN_FAIL,
    HOOK_REPLACE_CANONICAL
} hook_action_t;

static retirement_guard_clear_test_stage_t hook_stage;
static hook_action_t hook_action;
static bool hook_armed;
static unsigned char hook_replacement[GUARD_MAX_BYTES];
static size_t hook_replacement_length;

static int guard_fault_hook(
    retirement_guard_clear_test_stage_t stage, int descriptor,
    const char *marker_name) {
    (void)marker_name;
    if (!hook_armed || stage != hook_stage) return 0;
    hook_armed = false;
    if (hook_action == HOOK_SYNC_THEN_FAIL &&
        fsync(descriptor) != 0) {
        return -1;
    }
    if (hook_action == HOOK_REPLACE_CANONICAL) {
        return guard_atomic_replace_at(
            descriptor, GUARD_NAME, hook_replacement,
            hook_replacement_length);
    }
    errno = EIO;
    return -1;
}

static void guard_arm_hook(
    retirement_guard_clear_test_stage_t stage, hook_action_t action) {
    hook_stage = stage;
    hook_action = action;
    hook_armed = true;
    (void)gitswitch_test_set_retirement_guard_clear_hook(
        guard_fault_hook);
}

static bool guard_probe(const guard_fixture_t *fixture, bool *blocked) {
    return fixture && blocked &&
           config_retirement_guard_probe(
               fixture->config_path, blocked) == 0;
}

TEST(completion_keeps_canonical_generation_and_unblocks) {
    guard_fixture_t fixture;
    struct stat after;
    bool blocked = true;
    int unexpected = -1;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);
    CHECK_EQ_INT(stat(fixture.marker_path, &after), 0);
    CHECK(ts_same_identity(&fixture.marker_identity, &after));
    CHECK_EQ_INT((long)guard_read_file(
                     fixture.marker_path, hook_replacement,
                     sizeof(hook_replacement)),
                 (long)fixture.marker_length);
    CHECK(memcmp(hook_replacement, fixture.marker_data,
                 fixture.marker_length) == 0);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    CHECK(access(fixture.stage_path, F_OK) != 0 && errno == ENOENT);
    CHECK_EQ_INT(guard_count_retirement_entries(
                     fixture.directory, &unexpected), 3);
    CHECK_EQ_INT(unexpected, 0);
    guard_fixture_cleanup(&fixture);
}

TEST(prepublication_sync_failure_stays_blocked_and_converges) {
    guard_fixture_t fixture;
    bool blocked = false;
    int unexpected = -1;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    guard_arm_hook(RETIREMENT_GUARD_CLEAR_BEFORE_FILE_SYNC, HOOK_FAIL);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(fixture.guard != NULL);
    CHECK(hook_armed == false);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);
    CHECK_EQ_INT(guard_count_retirement_entries(
                     fixture.directory, &unexpected), 3);
    CHECK_EQ_INT(unexpected, 0);

    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(fixture.guard == NULL);
    blocked = true;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    CHECK(access(fixture.stage_path, F_OK) != 0 && errno == ENOENT);
    guard_fixture_cleanup(&fixture);
}

static void exercise_postpublication_ack(
    retirement_guard_clear_test_stage_t stage, hook_action_t action) {
    guard_fixture_t fixture;
    bool blocked = true;
    int unexpected = -1;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    guard_arm_hook(stage, action);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(fixture.guard == NULL);
    CHECK(!hook_armed);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    CHECK(guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    CHECK_EQ_INT(guard_count_retirement_entries(
                     fixture.directory, &unexpected), 3);
    CHECK_EQ_INT(unexpected, 0);
    guard_fixture_cleanup(&fixture);
}

TEST(postpublication_sync_failures_are_committed) {
    exercise_postpublication_ack(
        RETIREMENT_GUARD_CLEAR_AFTER_PUBLISH, HOOK_FAIL);
    exercise_postpublication_ack(
        RETIREMENT_GUARD_CLEAR_BEFORE_DIR_SYNC, HOOK_FAIL);
    exercise_postpublication_ack(
        RETIREMENT_GUARD_CLEAR_BEFORE_DIR_SYNC,
        HOOK_SYNC_THEN_FAIL);
    exercise_postpublication_ack(
        RETIREMENT_GUARD_CLEAR_AFTER_DIR_SYNC, HOOK_FAIL);
}

TEST(mixed_generation_probe_never_unblocks) {
    guard_fixture_t fixture;
    config_retirement_guard_t *recovery = NULL;
    bool blocked = true;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    CHECK(guard_mutate_token(
        fixture.marker_data, fixture.marker_length,
        hook_replacement));
    hook_replacement_length = fixture.marker_length;

    guard_arm_hook(
        RETIREMENT_GUARD_PAIR_AFTER_MARKER_READ,
        HOOK_REPLACE_CANONICAL);
    CHECK_EQ_INT(config_retirement_guard_probe(
                     fixture.config_path, &blocked), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(blocked);
    blocked = false;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    CHECK(!guard_files_equal(
        fixture.marker_path, fixture.completion_path));

    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &recovery), 0);
    CHECK(!config_retirement_guard_was_created(recovery));
    CHECK_EQ_INT(config_retirement_guard_clear(&recovery), 0);
    blocked = true;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(canonical_replacement_before_publication_fails_closed) {
    guard_fixture_t fixture;
    config_retirement_guard_t *recovery = NULL;
    unsigned char observed[GUARD_MAX_BYTES];
    bool blocked = false;
    size_t observed_length;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK(guard_mutate_token(
        fixture.marker_data, fixture.marker_length,
        hook_replacement));
    hook_replacement_length = fixture.marker_length;
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_BEFORE_PUBLISH,
        HOOK_REPLACE_CANONICAL);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK(fixture.guard != NULL);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    observed_length = guard_read_file(
        fixture.marker_path, observed, sizeof(observed));
    CHECK_EQ_INT((long)observed_length,
                 (long)hook_replacement_length);
    CHECK(memcmp(observed, hook_replacement,
                 hook_replacement_length) == 0);

    config_retirement_guard_abandon(&fixture.guard);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &recovery), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&recovery), 0);
    blocked = true;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(settled_pair_rotates_fresh_and_residue_is_bounded) {
    guard_fixture_t fixture;
    unsigned char previous[GUARD_MAX_BYTES];
    size_t previous_length;
    bool blocked = true;
    int unexpected = -1;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    previous_length = guard_read_file(
        fixture.marker_path, previous, sizeof(previous));
    CHECK(previous_length > 0U);

    for (unsigned int cycle = 0U; cycle < 64U; cycle++) {
        unsigned char current[GUARD_MAX_BYTES];
        size_t current_length;

        CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                         fixture.config_path, CONFIG_RETIREMENT_RESET,
                         &fixture.owner, 1U, &fixture.guard), 0);
        CHECK(config_retirement_guard_was_created(fixture.guard));
        current_length = guard_read_file(
            fixture.marker_path, current, sizeof(current));
        CHECK(current_length > 0U);
        CHECK(current_length != previous_length ||
              memcmp(current, previous, current_length) != 0);
        blocked = false;
        CHECK(guard_probe(&fixture, &blocked));
        CHECK(blocked);
        CHECK(!guard_files_equal(
            fixture.marker_path, fixture.completion_path));
        CHECK(access(fixture.stage_path, F_OK) != 0 && errno == ENOENT);
        CHECK_EQ_INT(guard_count_retirement_entries(
                         fixture.directory, &unexpected), 3);
        CHECK_EQ_INT(unexpected, 0);

        CHECK_EQ_INT(config_retirement_guard_clear(
                         &fixture.guard), 0);
        blocked = true;
        CHECK(guard_probe(&fixture, &blocked));
        CHECK(!blocked);
        CHECK(guard_files_equal(
            fixture.marker_path, fixture.completion_path));
        memcpy(previous, current, current_length);
        previous_length = current_length;
    }
    guard_fixture_cleanup(&fixture);
}

TEST(lone_and_mismatched_certificates_block) {
    guard_fixture_t fixture;
    unsigned char completion[GUARD_MAX_BYTES];
    unsigned char mismatched[GUARD_MAX_BYTES];
    size_t completion_length;
    bool blocked = false;
    int directory_fd;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    completion_length = guard_read_file(
        fixture.completion_path, completion, sizeof(completion));
    CHECK(completion_length > 0U);
    CHECK_EQ_INT(unlink(fixture.marker_path), 0);
    directory_fd = open(fixture.directory,
                        O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    CHECK(directory_fd >= 0);
    if (directory_fd >= 0) {
        CHECK_EQ_INT(fsync(directory_fd), 0);
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd, GUARD_NAME,
                         completion, completion_length), 0);
        CHECK(guard_mutate_token(
            completion, completion_length, mismatched));
        CHECK_EQ_INT(guard_atomic_replace_at(
                         directory_fd, COMPLETE_NAME,
                         mismatched, completion_length), 0);
        CHECK_EQ_INT(close(directory_fd), 0);
    }
    blocked = false;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(lifecycle_lock_serializes_guard_owners) {
    guard_fixture_t fixture;
    config_retirement_guard_t *second = NULL;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &second), -1);
    CHECK(second == NULL);
    CHECK_EQ_INT(errno, EBUSY);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);
    guard_fixture_cleanup(&fixture);
}

TEST(unproven_install_is_not_adopted_until_directory_sync_succeeds) {
    guard_fixture_t fixture;
    config_retirement_guard_t *retry = NULL;
    unsigned char retained[GUARD_MAX_BYTES];
    struct stat retained_identity;
    size_t retained_length;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), 0);

    guard_arm_hook(
        RETIREMENT_GUARD_INSTALL_BEFORE_DIR_SYNC, HOOK_FAIL);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &retry), -1);
    CHECK(retry == NULL);
    CHECK(!hook_armed);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    retained_length = guard_read_file(
        fixture.marker_path, retained, sizeof(retained));
    CHECK(retained_length > 0U);
    CHECK_EQ_INT(stat(fixture.marker_path, &retained_identity), 0);
    CHECK(!guard_files_equal(
        fixture.marker_path, fixture.completion_path));
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);

    guard_arm_hook(
        RETIREMENT_GUARD_INSTALL_BEFORE_DIR_SYNC, HOOK_FAIL);
    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &retry), -1);
    CHECK(retry == NULL);
    CHECK(!hook_armed);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    CHECK_EQ_INT((long)guard_read_file(
                     fixture.marker_path, hook_replacement,
                     sizeof(hook_replacement)),
                 (long)retained_length);
    CHECK(memcmp(retained, hook_replacement, retained_length) == 0);
    {
        struct stat after;

        CHECK_EQ_INT(stat(fixture.marker_path, &after), 0);
        CHECK(ts_same_identity(&retained_identity, &after));
    }
    blocked = false;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);

    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &retry), 0);
    CHECK(retry != NULL);
    CHECK(!config_retirement_guard_was_created(retry));
    CHECK_EQ_INT(config_retirement_guard_clear(&retry), 0);
    blocked = true;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    guard_fixture_cleanup(&fixture);
}

TEST(abandon_after_failed_clear_never_reopens) {
    guard_fixture_t fixture;
    config_retirement_guard_t *recovery = NULL;
    bool blocked = false;

    CHECK_EQ_INT(guard_fixture_init(&fixture), 0);
    guard_arm_hook(
        RETIREMENT_GUARD_CLEAR_AFTER_STAGE_WRITE, HOOK_FAIL);
    CHECK_EQ_INT(config_retirement_guard_clear(&fixture.guard), -1);
    (void)gitswitch_test_set_retirement_guard_clear_hook(NULL);
    config_retirement_guard_abandon(&fixture.guard);
    CHECK(fixture.guard == NULL);
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(blocked);
    CHECK_EQ_INT(access(fixture.stage_path, F_OK), 0);

    CHECK_EQ_INT(config_retirement_guard_install_or_adopt(
                     fixture.config_path, CONFIG_RETIREMENT_RESET,
                     &fixture.owner, 1U, &recovery), 0);
    CHECK_EQ_INT(config_retirement_guard_clear(&recovery), 0);
    blocked = true;
    CHECK(guard_probe(&fixture, &blocked));
    CHECK(!blocked);
    guard_fixture_cleanup(&fixture);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(completion_keeps_canonical_generation_and_unblocks);
    RUN_TEST(prepublication_sync_failure_stays_blocked_and_converges);
    RUN_TEST(postpublication_sync_failures_are_committed);
    RUN_TEST(mixed_generation_probe_never_unblocks);
    RUN_TEST(canonical_replacement_before_publication_fails_closed);
    RUN_TEST(settled_pair_rotates_fresh_and_residue_is_bounded);
    RUN_TEST(lone_and_mismatched_certificates_block);
    RUN_TEST(lifecycle_lock_serializes_guard_owners);
    RUN_TEST(unproven_install_is_not_adopted_until_directory_sync_succeeds);
    RUN_TEST(abandon_after_failed_clear_never_reopens);
TEST_MAIN_END()
