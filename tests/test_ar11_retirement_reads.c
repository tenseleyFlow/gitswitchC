/* AR-11 M12: exact-file retirement reads distinguish clean absence from
 * indeterminate state, and a failed physical group authorizes no mutation. */
#include "test.h"
#include "error.h"
#include "git_ops.h"
#include "publication.h"
#include "utils.h"

#include <signal.h>

#define M12_INCARNATION \
    "1212121212121212121212121212121212121212121212121212121212121212"
#define M12_FINGERPRINT \
    "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333"
#define M12_SELECTOR "22223333"

typedef void *(*m12_snapshot_malloc_fn)(size_t size);
m12_snapshot_malloc_fn git_ops_test_set_snapshot_value_malloc_fn(
    m12_snapshot_malloc_fn fn);

enum m12_key_index {
    M12_SIGNING_KEY = 0,
    M12_SIGNING_ENABLED,
    M12_GPG_FORMAT,
    M12_GPG_PROGRAM,
    M12_KEY_COUNT
};

static const char *const m12_keys[M12_KEY_COUNT] = {
    GIT_CONFIG_USER_SIGNINGKEY,
    GIT_CONFIG_COMMIT_GPGSIGN,
    GIT_CONFIG_GPG_FORMAT,
    GIT_CONFIG_GPG_OPENPGP_PROGRAM
};

typedef enum {
    M12_READ_CLEAN_ABSENCE = 0,
    M12_READ_SPAWN_FAILURE,
    M12_READ_RUNNER_DIAGNOSTIC,
    M12_READ_SIGNAL,
    M12_READ_NONZERO_EXIT,
    M12_READ_TRUNCATED,
    M12_READ_MALFORMED_NUL,
    M12_READ_ALLOCATION_FAILURE
} m12_read_fault_t;

typedef struct {
    char path[MAX_PATH_LEN];
    bool present[M12_KEY_COUNT];
    size_t snapshot_reads;
    size_t scalar_reads;
    size_t unsets;
} m12_destination_t;

typedef struct {
    char root[MAX_PATH_LEN];
    char config_a[MAX_PATH_LEN];
    char config_b[MAX_PATH_LEN];
    char program[MAX_PATH_LEN];
    account_t account;
    publication_record_t records[2];
    const publication_record_t *record_ptrs[2];
} m12_fixture_t;

static m12_destination_t m12_destinations[2];
static char m12_program[MAX_PATH_LEN];
static m12_read_fault_t m12_fault;
static bool m12_unexpected_command;
static bool m12_unset_before_all_snapshots;
static size_t m12_allocation_calls;

static int m12_write_all(int fd, const char *contents, size_t length) {
    size_t written = 0U;

    while (written < length) {
        ssize_t result = write(fd, contents + written, length - written);

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

static int m12_write_file(const char *path, const char *contents,
                          mode_t mode) {
    size_t length;
    int fd;

    if (!path || !contents) return -1;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) return -1;
    length = strlen(contents);
    if (m12_write_all(fd, contents, length) != 0 || fsync(fd) != 0) {
        (void)close(fd);
        return -1;
    }
    return close(fd);
}

static int m12_make_record(publication_record_t *record,
                           const m12_fixture_t *fixture,
                           const char *config_path) {
    struct stat st;

    publication_record_init(record);
    record->account_id = fixture->account.id;
    record->scope = PUBLICATION_SCOPE_GLOBAL;
    record->state = PUBLICATION_STATE_PUBLISHED;
    record->capabilities = PUBLICATION_CAP_DESTINATION |
                           PUBLICATION_CAP_POST_GENERATION |
                           PUBLICATION_CAP_GPG_FINGERPRINT |
                           PUBLICATION_CAP_GPG_PROGRAM |
                           PUBLICATION_CAP_GPG_SELECTOR;
    if (safe_strncpy(record->account_incarnation,
                     fixture->account.incarnation,
                     sizeof(record->account_incarnation)) != 0 ||
        safe_strncpy(record->config_path, config_path,
                     sizeof(record->config_path)) != 0 ||
        stat(fixture->root, &st) != 0) {
        return -1;
    }
    publication_identity_from_stat(&record->config_parent, &st);
    if (stat(config_path, &st) != 0) return -1;
    publication_identity_from_stat(&record->post_config, &st);
    if (safe_strncpy(record->gpg_fingerprint, M12_FINGERPRINT,
                     sizeof(record->gpg_fingerprint)) != 0 ||
        safe_strncpy(record->gpg_selector, M12_SELECTOR,
                     sizeof(record->gpg_selector)) != 0 ||
        safe_strncpy(record->gpg_program, fixture->program,
                     sizeof(record->gpg_program)) != 0 ||
        stat(fixture->program, &st) != 0) {
        return -1;
    }
    publication_identity_from_stat(&record->gpg_program_identity, &st);
    return publication_record_validate(record);
}

static int m12_fixture_init(m12_fixture_t *fixture) {
    char root_template[] = "/tmp/gsw-ar11-m12-XXXXXX";

    memset(fixture, 0, sizeof(*fixture));
    if (!ts_mkdtemp(root_template) ||
        safe_strncpy(fixture->root, root_template,
                     sizeof(fixture->root)) != 0 ||
        ts_canonicalize_dir_path(fixture->root,
                                 sizeof(fixture->root)) != 0 ||
        safe_snprintf(fixture->config_a, sizeof(fixture->config_a),
                      "%s/config-a", fixture->root) != 0 ||
        safe_snprintf(fixture->config_b, sizeof(fixture->config_b),
                      "%s/config-b", fixture->root) != 0 ||
        safe_snprintf(fixture->program, sizeof(fixture->program),
                      "%s/gpg-program", fixture->root) != 0 ||
        m12_write_file(fixture->config_a, "[fixture]\nvalue = 1\n",
                       0600) != 0 ||
        m12_write_file(fixture->config_b, "[fixture]\nvalue = 2\n",
                       0600) != 0 ||
        m12_write_file(fixture->program, "#!/bin/sh\nexit 0\n", 0700) != 0) {
        return -1;
    }
    fixture->account.id = UINT32_C(41);
    fixture->account.incarnation_persisted = true;
    fixture->account.gpg_enabled = true;
    fixture->account.gpg_signing_enabled = true;
    if (safe_strncpy(fixture->account.incarnation, M12_INCARNATION,
                     sizeof(fixture->account.incarnation)) != 0 ||
        safe_strncpy(fixture->account.name, "alice",
                     sizeof(fixture->account.name)) != 0 ||
        safe_strncpy(fixture->account.gpg_key_id, M12_SELECTOR,
                     sizeof(fixture->account.gpg_key_id)) != 0 ||
        m12_make_record(&fixture->records[0], fixture,
                        fixture->config_a) != 0 ||
        m12_make_record(&fixture->records[1], fixture,
                        fixture->config_b) != 0) {
        return -1;
    }
    fixture->record_ptrs[0] = &fixture->records[0];
    fixture->record_ptrs[1] = &fixture->records[1];
    return 0;
}

static int m12_key_slot(const char *key) {
    if (!key) return -1;
    for (int i = 0; i < M12_KEY_COUNT; i++) {
        if (strcmp(key, m12_keys[i]) == 0) return i;
    }
    return -1;
}

static const char *m12_key_value(int slot) {
    switch (slot) {
        case M12_SIGNING_KEY: return M12_FINGERPRINT;
        case M12_SIGNING_ENABLED: return "true";
        case M12_GPG_FORMAT: return "openpgp";
        case M12_GPG_PROGRAM: return m12_program;
        default: return NULL;
    }
}

static int m12_publish(const run_opts_t *opts, run_result_t *result,
                       const void *bytes, size_t length, bool spawned,
                       int exit_code, int term_signal, bool truncated) {
    size_t copied = 0U;

    if (opts && opts->out && opts->out_size > 0U && bytes) {
        copied = length;
        if (copied >= opts->out_size) copied = opts->out_size - 1U;
        if (copied > 0U) memcpy(opts->out, bytes, copied);
        opts->out[copied] = '\0';
    }
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = spawned;
        result->exit_code = exit_code;
        result->term_signal = term_signal;
        result->out_len = copied;
        result->out_truncated = truncated || copied != length;
    }
    return spawned && term_signal == 0 && exit_code == 0 ? 0 : -1;
}

static int m12_append_record(char *listing, size_t listing_size,
                             size_t *used, const char *key,
                             const char *value) {
    size_t key_length = strlen(key);
    size_t value_length = strlen(value);

    if (*used > listing_size ||
        key_length + value_length + 2U > listing_size - *used) {
        return -1;
    }
    memcpy(listing + *used, key, key_length);
    *used += key_length;
    listing[(*used)++] = '\n';
    memcpy(listing + *used, value, value_length);
    *used += value_length;
    listing[(*used)++] = '\0';
    return 0;
}

static int m12_publish_valid_listing(const run_opts_t *opts,
                                     run_result_t *result,
                                     const m12_destination_t *destination) {
    char listing[MAX_PATH_LEN + 512U];
    size_t used = 0U;

    for (int slot = 0; slot < M12_KEY_COUNT; slot++) {
        if (destination->present[slot] &&
            m12_append_record(listing, sizeof(listing), &used,
                              m12_keys[slot], m12_key_value(slot)) != 0) {
            return m12_publish(opts, result, NULL, 0U, true, 2, 0,
                               false);
        }
    }
    return m12_publish(opts, result, listing, used, true, 0, 0, false);
}

/* Both the pre-seed and runner paths call this exact setter so their complete
 * contexts are byte-identical. M12 must still recognize the latter as a fresh
 * causal diagnostic on a consecutive retry. */
static void m12_set_runner_diagnostic(void) {
    set_error(ERR_SYSTEM_COMMAND_FAILED,
              "m12 preserved runner diagnostic");
}

static int m12_publish_read_fault(const run_opts_t *opts,
                                  run_result_t *result,
                                  bool snapshot_read) {
    static const char nonzero[] = "m12 injected read failure";
    static const char truncated[] = M12_FINGERPRINT "\n";
    static const char malformed_scalar[] =
        M12_FINGERPRINT "\0foreign-value\n";
    char malformed_listing[256];
    size_t used = 0U;

    switch (m12_fault) {
        case M12_READ_SPAWN_FAILURE:
            return m12_publish(opts, result, NULL, 0U, false, -1, 0,
                               false);
        case M12_READ_RUNNER_DIAGNOSTIC:
            m12_set_runner_diagnostic();
            return m12_publish(opts, result, NULL, 0U, false, -1, 0,
                               false);
        case M12_READ_SIGNAL:
            return m12_publish(opts, result, NULL, 0U, true, -1,
                               SIGTERM, false);
        case M12_READ_NONZERO_EXIT:
            return m12_publish(opts, result, nonzero,
                               sizeof(nonzero) - 1U, true, 128, 0, false);
        case M12_READ_TRUNCATED:
            return m12_publish(opts, result, truncated,
                               sizeof(truncated) - 1U, true, 0, 0, true);
        case M12_READ_MALFORMED_NUL:
            if (!snapshot_read) {
                return m12_publish(opts, result, malformed_scalar,
                                   sizeof(malformed_scalar) - 1U,
                                   true, 0, 0, false);
            }
            if (m12_append_record(malformed_listing,
                                  sizeof(malformed_listing), &used,
                                  GIT_CONFIG_USER_SIGNINGKEY,
                                  M12_FINGERPRINT) != 0) {
                return m12_publish(opts, result, NULL, 0U, true, 2, 0,
                                   false);
            }
            memcpy(malformed_listing + used,
                   GIT_CONFIG_COMMIT_GPGSIGN "\ntrue",
                   sizeof(GIT_CONFIG_COMMIT_GPGSIGN "\ntrue") - 1U);
            used += sizeof(GIT_CONFIG_COMMIT_GPGSIGN "\ntrue") - 1U;
            return m12_publish(opts, result, malformed_listing, used,
                               true, 0, 0, false);
        default:
            return -2;
    }
}

static m12_destination_t *m12_find_destination(const char *path) {
    if (!path) return NULL;
    for (size_t i = 0; i < 2U; i++) {
        if (strcmp(path, m12_destinations[i].path) == 0) {
            return &m12_destinations[i];
        }
    }
    return NULL;
}

static int m12_runner(const char *const argv[], const run_opts_t *opts,
                      run_result_t *result) {
    m12_destination_t *destination;
    int slot;

    if (result) memset(result, 0, sizeof(*result));
    if (!argv || !argv[0] || !ts_command_is(argv[0], "git") ||
        !argv[1] || strcmp(argv[1], "config") != 0 ||
        !argv[2] || strcmp(argv[2], "--file") != 0 || !argv[3]) {
        m12_unexpected_command = true;
        return m12_publish(opts, result, NULL, 0U, true, 2, 0, false);
    }
    destination = m12_find_destination(argv[3]);
    if (!destination) {
        m12_unexpected_command = true;
        return m12_publish(opts, result, NULL, 0U, true, 2, 0, false);
    }

    /* M12's authoritative read is one exact binary snapshot per physical
     * destination. Keep the legacy scalar branch only so this suite can
     * demonstrate the pre-fix false-absence behavior. */
    if (argv[4] && strcmp(argv[4], "--list") == 0) {
        if (!argv[5] || strcmp(argv[5], "-z") != 0 ||
            !argv[6] || strcmp(argv[6], "--no-includes") != 0 ||
            argv[7]) {
            m12_unexpected_command = true;
            return m12_publish(opts, result, NULL, 0U, true, 2, 0, false);
        }
        destination->snapshot_reads++;
        if (destination == &m12_destinations[0] &&
            m12_fault != M12_READ_CLEAN_ABSENCE &&
            m12_fault != M12_READ_ALLOCATION_FAILURE) {
            return m12_publish_read_fault(opts, result, true);
        }
        return m12_publish_valid_listing(opts, result, destination);
    }

    if (!argv[4] || strcmp(argv[4], "--no-includes") != 0 ||
        !argv[5]) {
        m12_unexpected_command = true;
        return m12_publish(opts, result, NULL, 0U, true, 2, 0, false);
    }
    if (strcmp(argv[5], "--get-all") == 0) {
        const char *value;

        if (!argv[6] || argv[7]) {
            m12_unexpected_command = true;
            return m12_publish(opts, result, NULL, 0U, true, 2, 0,
                               false);
        }
        slot = m12_key_slot(argv[6]);
        if (slot < 0) {
            m12_unexpected_command = true;
            return m12_publish(opts, result, NULL, 0U, true, 2, 0,
                               false);
        }
        destination->scalar_reads++;
        if (destination == &m12_destinations[0] &&
            m12_fault != M12_READ_CLEAN_ABSENCE &&
            m12_fault != M12_READ_ALLOCATION_FAILURE) {
            return m12_publish_read_fault(opts, result, false);
        }
        if (!destination->present[slot]) {
            return m12_publish(opts, result, NULL, 0U, true, 1, 0,
                               false);
        }
        value = m12_key_value(slot);
        return m12_publish(opts, result, value, strlen(value), true, 0, 0,
                           false);
    }
    if (strcmp(argv[5], "--fixed-value") == 0 && argv[6] &&
        strcmp(argv[6], "--unset-all") == 0 && argv[7] && argv[8] &&
        !argv[9]) {
        slot = m12_key_slot(argv[7]);
        if (slot < 0 || strcmp(argv[8], m12_key_value(slot)) != 0) {
            m12_unexpected_command = true;
            return m12_publish(opts, result, NULL, 0U, true, 2, 0,
                               false);
        }
        if (m12_destinations[0].snapshot_reads == 0U ||
            m12_destinations[1].snapshot_reads == 0U) {
            m12_unset_before_all_snapshots = true;
        }
        destination->unsets++;
        if (!destination->present[slot]) {
            return m12_publish(opts, result, NULL, 0U, true, 5, 0,
                               false);
        }
        destination->present[slot] = false;
        return m12_publish(opts, result, NULL, 0U, true, 0, 0, false);
    }

    m12_unexpected_command = true;
    return m12_publish(opts, result, NULL, 0U, true, 2, 0, false);
}

static void *m12_fail_first_snapshot_allocation(size_t size) {
    m12_allocation_calls++;
    if (m12_allocation_calls == 1U) return NULL;
    return malloc(size);
}

static bool m12_destination_is_present(size_t index) {
    for (int slot = 0; slot < M12_KEY_COUNT; slot++) {
        if (!m12_destinations[index].present[slot]) return false;
    }
    return true;
}

static bool m12_destination_is_absent(size_t index) {
    for (int slot = 0; slot < M12_KEY_COUNT; slot++) {
        if (m12_destinations[index].present[slot]) return false;
    }
    return true;
}

static bool m12_error_contains(const char *needle) {
    const error_context_t *error = get_last_error();

    return strstr(error->message, needle) != NULL ||
           strstr(error->details, needle) != NULL;
}

static void m12_model_destinations(const m12_fixture_t *fixture,
                                   bool first_present) {
    memset(m12_destinations, 0, sizeof(m12_destinations));
    CHECK_EQ_INT(safe_strncpy(m12_destinations[0].path,
                              fixture->config_a,
                              sizeof(m12_destinations[0].path)), 0);
    CHECK_EQ_INT(safe_strncpy(m12_destinations[1].path,
                              fixture->config_b,
                              sizeof(m12_destinations[1].path)), 0);
    CHECK_EQ_INT(safe_strncpy(m12_program, fixture->program,
                              sizeof(m12_program)), 0);
    for (int slot = 0; slot < M12_KEY_COUNT; slot++) {
        m12_destinations[0].present[slot] = first_present;
        m12_destinations[1].present[slot] = true;
    }
    m12_unexpected_command = false;
    m12_unset_before_all_snapshots = false;
    m12_allocation_calls = 0U;
}

static void m12_run_fault_case(m12_read_fault_t fault,
                               const char *causal_text,
                               bool seed_identical_diagnostic) {
    m12_snapshot_malloc_fn previous_malloc = NULL;
    command_runner_fn previous_runner;
    m12_fixture_t fixture;
    size_t cleared = 99U;
    int result;

    if (m12_fixture_init(&fixture) != 0) {
        CHECK(0 && "M12 fixture initialization");
        return;
    }
    m12_model_destinations(&fixture, true);
    m12_fault = fault;
    clear_error();
    if (seed_identical_diagnostic) m12_set_runner_diagnostic();
    previous_runner = run_set_runner(m12_runner);
    if (fault == M12_READ_ALLOCATION_FAILURE) {
        previous_malloc = git_ops_test_set_snapshot_value_malloc_fn(
            m12_fail_first_snapshot_allocation);
    }
    result = git_retire_account_identity_publications(
        &fixture.account, fixture.record_ptrs, 2U, &cleared);
    if (fault == M12_READ_ALLOCATION_FAILURE) {
        (void)git_ops_test_set_snapshot_value_malloc_fn(previous_malloc);
    }
    (void)run_set_runner(previous_runner);

    CHECK_EQ_INT(result, -1);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK_EQ_INT((long)m12_destinations[0].unsets, 0);
    CHECK(m12_destination_is_present(0U));
    CHECK_EQ_INT((long)m12_destinations[1].unsets, 0);
    CHECK(m12_destination_is_present(1U));
    CHECK(m12_destinations[0].snapshot_reads > 0U);
    CHECK(m12_destinations[1].snapshot_reads > 0U);
    CHECK(!m12_unexpected_command);
    if (fault == M12_READ_ALLOCATION_FAILURE) {
        CHECK(m12_allocation_calls > 0U);
        CHECK_EQ_INT(get_last_error()->code, ERR_MEMORY_ALLOCATION);
    } else if (fault == M12_READ_RUNNER_DIAGNOSTIC) {
        CHECK_EQ_INT(get_last_error()->code, ERR_SYSTEM_COMMAND_FAILED);
    } else {
        CHECK_EQ_INT(get_last_error()->code, ERR_GIT_CONFIG_FAILED);
    }
    CHECK_EQ_INT((long)m12_destinations[0].scalar_reads, 0);
    CHECK_EQ_INT((long)m12_destinations[1].scalar_reads, 0);
    CHECK(!m12_unset_before_all_snapshots);
    CHECK(m12_error_contains(causal_text));
    CHECK(m12_error_contains("cleared 0") ||
          m12_error_contains("retirement summary"));
    ts_rm_rf(fixture.root);
}

TEST(clean_absence_is_idempotent_and_does_not_block_healthy_group) {
    command_runner_fn previous_runner;
    m12_fixture_t fixture;
    size_t cleared = 99U;
    int result;

    if (m12_fixture_init(&fixture) != 0) {
        CHECK(0 && "M12 fixture initialization");
        return;
    }
    m12_model_destinations(&fixture, false);
    m12_fault = M12_READ_CLEAN_ABSENCE;
    clear_error();
    previous_runner = run_set_runner(m12_runner);
    result = git_retire_account_identity_publications(
        &fixture.account, fixture.record_ptrs, 2U, &cleared);
    (void)run_set_runner(previous_runner);

    CHECK_EQ_INT(result, 0);
    CHECK_EQ_INT((long)cleared, M12_KEY_COUNT);
    CHECK_EQ_INT((long)m12_destinations[0].unsets, 0);
    CHECK(m12_destination_is_absent(0U));
    CHECK_EQ_INT((long)m12_destinations[1].unsets, M12_KEY_COUNT);
    CHECK(m12_destination_is_absent(1U));
    CHECK(m12_destinations[0].snapshot_reads > 0U);
    CHECK(m12_destinations[1].snapshot_reads > 0U);
    CHECK_EQ_INT((long)m12_destinations[0].scalar_reads, 0);
    CHECK_EQ_INT((long)m12_destinations[1].scalar_reads, 0);
    CHECK(!m12_unset_before_all_snapshots);
    CHECK(!m12_unexpected_command);
    CHECK_EQ_INT(get_last_error()->code, ERR_SUCCESS);
    ts_rm_rf(fixture.root);
}

TEST(spawn_failure_blocks_all_mutation) {
    m12_run_fault_case(M12_READ_SPAWN_FAILURE, "started", false);
}

TEST(signal_termination_blocks_all_mutation) {
    m12_run_fault_case(M12_READ_SIGNAL, "signal", false);
}

TEST(runner_diagnostic_is_not_replaced_by_synthesized_status) {
    m12_run_fault_case(M12_READ_RUNNER_DIAGNOSTIC,
                       "m12 preserved runner diagnostic", false);
}

TEST(identical_consecutive_runner_diagnostic_remains_causal) {
    m12_run_fault_case(M12_READ_RUNNER_DIAGNOSTIC,
                       "m12 preserved runner diagnostic", true);
}

TEST(nonzero_exit_blocks_all_mutation) {
    /* Binary stdout is intentionally isolated from diagnostics. Child status
     * is the stable causal witness; arbitrary captured bytes are not. */
    m12_run_fault_case(M12_READ_NONZERO_EXIT, "status 128", false);
}

TEST(truncated_output_blocks_all_mutation) {
    m12_run_fault_case(M12_READ_TRUNCATED, "exceeds", false);
}

TEST(malformed_nul_listing_blocks_all_mutation) {
    m12_run_fault_case(M12_READ_MALFORMED_NUL, "Malformed", false);
}

TEST(allocation_failure_blocks_all_mutation) {
    m12_run_fault_case(M12_READ_ALLOCATION_FAILURE, "memory", false);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(clean_absence_is_idempotent_and_does_not_block_healthy_group);
    RUN_TEST(spawn_failure_blocks_all_mutation);
    RUN_TEST(runner_diagnostic_is_not_replaced_by_synthesized_status);
    RUN_TEST(identical_consecutive_runner_diagnostic_remains_causal);
    RUN_TEST(signal_termination_blocks_all_mutation);
    RUN_TEST(nonzero_exit_blocks_all_mutation);
    RUN_TEST(truncated_output_blocks_all_mutation);
    RUN_TEST(malformed_nul_listing_blocks_all_mutation);
    RUN_TEST(allocation_failure_blocks_all_mutation);
TEST_MAIN_END()
