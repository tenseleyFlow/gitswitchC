/* AR-11 M8-M10: durable Git-publication provenance is an exact, versioned
 * ownership record. These tests stay on the public record/ledger/config APIs
 * so persistence layout can evolve without weakening the causal contract. */
#include "test.h"
#include "accounts.h"
#include "config.h"
#include "error.h"
#include "publication.h"
#include "toml_parser.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>

#define FINGERPRINT_A "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333"
#define FINGERPRINT_B "9999888877776666555544440000111122223333"
#define SELECTOR_A "22223333"
#define SELECTOR_64 \
    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
#define SSH_PROGRAM_A "/usr/bin/ssh"
#define SSH_PROGRAM_B "/usr/bin/scp"
#define SSH_COMMAND_A \
    "'/usr/bin/ssh' -i '/tmp/ar11 publication key' -F '/dev/null' " \
    "-o IdentitiesOnly=yes"
#define INCARNATION_A \
    "1111111111111111111111111111111111111111111111111111111111111111"
#define INCARNATION_B \
    "2222222222222222222222222222222222222222222222222222222222222222"

#define CHECK_LOOKUP_STATUS(call, expected) do {                             \
    publication_lookup_status_t lookup_status_ = (call);                    \
    CHECK(lookup_status_ == (expected));                                     \
} while (0)

static const char legacy_two_account_document[] =
    "[settings]\n"
    "default_scope = \"global\"\n"
    "\n"
    "[accounts.1]\n"
    "name = \"alice\"\n"
    "email = \"alice@example.test\"\n"
    "preferred_scope = \"global\"\n"
    "\n"
    "[accounts.2]\n"
    "name = \"bob\"\n"
    "email = \"bob@example.test\"\n"
    "preferred_scope = \"local\"\n";

static size_t incarnation_generator_calls;
static size_t incarnation_generator_success_limit;

static int deterministic_incarnation_generator(
    char incarnation[ACCOUNT_INCARNATION_LEN]) {
    const char *value;

    incarnation_generator_calls++;
    if (incarnation_generator_calls > incarnation_generator_success_limit) {
        errno = EIO;
        set_error(ERR_FILE_IO, "Injected account incarnation entropy failure");
        return -1;
    }
    value = incarnation_generator_calls == 1U
        ? INCARNATION_A : INCARNATION_B;
    memcpy(incarnation, value, ACCOUNT_INCARNATION_LEN);
    return 0;
}

static void fill_identity(publication_identity_t *identity, uintmax_t inode,
                          uintmax_t mode, uintmax_t size) {
    memset(identity, 0, sizeof(*identity));
    identity->present = true;
    identity->device = UINTMAX_C(17);
    identity->inode = inode;
    identity->mode = mode;
    identity->uid = (uintmax_t)geteuid();
    identity->gid = (uintmax_t)getegid();
    identity->link_count = UINTMAX_C(1);
    identity->size = size;
    identity->mtime_seconds = INT64_C(1721000000) + (int64_t)inode;
    identity->mtime_nanoseconds = UINT32_C(123456789);
    identity->ctime_seconds = INT64_C(1722000000) + (int64_t)inode;
    identity->ctime_nanoseconds = UINT32_C(987654321);
}

static void fill_complete_gpg_tuple(publication_record_t *record,
                                    const char *selector) {
    record->capabilities |= PUBLICATION_CAP_GPG_FINGERPRINT |
                            PUBLICATION_CAP_GPG_PROGRAM |
                            PUBLICATION_CAP_GPG_SELECTOR;
    snprintf(record->gpg_selector, sizeof(record->gpg_selector), "%s",
             selector);
    snprintf(record->gpg_program, sizeof(record->gpg_program), "%s",
             "/usr/bin/gpg");
    fill_identity(&record->gpg_program_identity, UINTMAX_C(104),
                  (uintmax_t)(S_IFREG | 0555), UINTMAX_C(267104));
}

static void fill_complete_ssh_tuple(publication_record_t *record) {
    record->capabilities |= PUBLICATION_CAP_SSH_COMMAND |
                            PUBLICATION_CAP_SSH_PROGRAM;
    snprintf(record->ssh_command, sizeof(record->ssh_command), "%s",
             SSH_COMMAND_A);
    snprintf(record->ssh_program, sizeof(record->ssh_program), "%s",
             SSH_PROGRAM_A);
    fill_identity(&record->ssh_program_identity, UINTMAX_C(105),
                  (uintmax_t)(S_IFREG | 0555), UINTMAX_C(112640));
}

static void fill_gpg_record(publication_record_t *record,
                            const char *repository_path,
                            const char *fingerprint) {
    publication_record_init(record);
    record->account_id = UINT32_C(41);
    snprintf(record->account_incarnation,
             sizeof(record->account_incarnation), "%s", INCARNATION_A);
    record->scope = PUBLICATION_SCOPE_LOCAL;
    snprintf(record->config_path, sizeof(record->config_path),
             "%s", "/tmp/ar11-publication/repository/.git/config");
    fill_identity(&record->config_parent, UINTMAX_C(101),
                  (uintmax_t)(S_IFDIR | 0700), UINTMAX_C(0));
    snprintf(record->repository_path, sizeof(record->repository_path),
             "%s", repository_path);
    fill_identity(&record->repository, UINTMAX_C(102),
                  (uintmax_t)(S_IFDIR | 0700), UINTMAX_C(0));
    fill_identity(&record->post_config, UINTMAX_C(103),
                  (uintmax_t)(S_IFREG | 0600), UINTMAX_C(211));
    record->capabilities = PUBLICATION_CAP_DESTINATION |
                           PUBLICATION_CAP_POST_GENERATION;
    snprintf(record->gpg_fingerprint, sizeof(record->gpg_fingerprint),
             "%s", fingerprint);
    fill_complete_gpg_tuple(record, SELECTOR_A);
    record->state = PUBLICATION_STATE_PUBLISHED;
}

static void fill_ssh_record(publication_record_t *record) {
    fill_gpg_record(record, "/tmp/ar11-publication/repository",
                    FINGERPRINT_A);
    record->capabilities &= ~(PUBLICATION_CAP_GPG_FINGERPRINT |
                              PUBLICATION_CAP_GPG_PROGRAM |
                              PUBLICATION_CAP_GPG_SELECTOR);
    record->gpg_fingerprint[0] = '\0';
    record->gpg_selector[0] = '\0';
    record->gpg_program[0] = '\0';
    memset(&record->gpg_program_identity, 0,
           sizeof(record->gpg_program_identity));
    fill_complete_ssh_tuple(record);
}

static void fill_global_gpg_record(publication_record_t *record,
                                   uint32_t account_id,
                                   const char *config_path,
                                   const char *fingerprint) {
    publication_record_init(record);
    record->account_id = account_id;
    snprintf(record->account_incarnation,
             sizeof(record->account_incarnation), "%s", INCARNATION_A);
    record->scope = PUBLICATION_SCOPE_GLOBAL;
    snprintf(record->config_path, sizeof(record->config_path), "%s",
             config_path);
    fill_identity(&record->config_parent, UINTMAX_C(301),
                  (uintmax_t)(S_IFDIR | 0700), UINTMAX_C(0));
    fill_identity(&record->post_config, UINTMAX_C(302),
                  (uintmax_t)(S_IFREG | 0600), UINTMAX_C(144));
    record->capabilities = PUBLICATION_CAP_DESTINATION |
                           PUBLICATION_CAP_POST_GENERATION;
    snprintf(record->gpg_fingerprint, sizeof(record->gpg_fingerprint),
             "%s", fingerprint);
    fill_complete_gpg_tuple(record, SELECTOR_A);
}

static int make_private_config_home(char *home, size_t home_size,
                                    char *config_path,
                                    size_t config_path_size,
                                    char *state_path,
                                    size_t state_path_size) {
    char config_parent[MAX_PATH_LEN];
    char config_dir[MAX_PATH_LEN];

    if ((size_t)snprintf(home, home_size,
                         "/tmp/gsw-ar11-publication.XXXXXX") >= home_size ||
        !ts_mkdtemp(home) ||
        ts_canonicalize_dir_path(home, home_size) != 0 ||
        (size_t)snprintf(config_parent, sizeof(config_parent), "%s/.config",
                         home) >= sizeof(config_parent) ||
        mkdir(config_parent, 0700) != 0 ||
        (size_t)snprintf(config_dir, sizeof(config_dir), "%s/gitswitch",
                         config_parent) >= sizeof(config_dir) ||
        mkdir(config_dir, 0700) != 0 ||
        (size_t)snprintf(config_path, config_path_size, "%s/accounts.toml",
                         config_dir) >= config_path_size ||
        (size_t)snprintf(state_path, state_path_size, "%s/.resume-hint",
                         config_dir) >= state_path_size) {
        return -1;
    }
    return 0;
}

static int write_private_bytes(const char *path, const void *data,
                               size_t length) {
    const unsigned char *bytes = data;
    size_t written = 0U;
    int fd;

    if (!path || (!data && length != 0U)) return -1;
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    while (written < length) {
        ssize_t count = write(fd, bytes + written, length - written);
        if (count > 0) written += (size_t)count;
        else if (count < 0 && errno == EINTR) continue;
        else {
            close(fd);
            return -1;
        }
    }
    return close(fd);
}

static int read_file_alloc(const char *path, unsigned char **data,
                           size_t *length) {
    struct stat st;
    unsigned char *buffer;
    size_t total = 0;
    int fd;

    if (!path || !data || !length || lstat(path, &st) != 0 ||
        st.st_size < 0 ||
        (uintmax_t)st.st_size > PUBLICATION_LEDGER_MAX_BYTES + 4096U) {
        return -1;
    }
    buffer = malloc((size_t)st.st_size + 1U);
    if (!buffer) return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        free(buffer);
        return -1;
    }
    while (total < (size_t)st.st_size) {
        ssize_t count = read(fd, buffer + total,
                             (size_t)st.st_size - total);
        if (count > 0) total += (size_t)count;
        else if (count < 0 && errno == EINTR) continue;
        else {
            close(fd);
            free(buffer);
            return -1;
        }
    }
    if (close(fd) != 0) {
        free(buffer);
        return -1;
    }
    buffer[total] = '\0';
    *data = buffer;
    *length = total;
    return 0;
}

static unsigned char *replace_identity_component(
    const unsigned char *serialized, size_t serialized_length,
    const char *field_prefix, size_t component_index,
    const char *replacement, size_t *replaced_length) {
    const unsigned char *field = NULL;
    const unsigned char *value;
    const unsigned char *newline;
    const unsigned char *component_start;
    const unsigned char *component_end;
    unsigned char *replaced;
    size_t prefix_length;
    size_t replacement_length;
    size_t before_length;
    size_t after_length;

    if (!serialized || !field_prefix || !replacement || !replaced_length ||
        component_index >= 11U) {
        return NULL;
    }
    *replaced_length = 0U;
    prefix_length = strlen(field_prefix);
    replacement_length = strlen(replacement);
    for (size_t i = 0; i + prefix_length <= serialized_length; i++) {
        if ((i == 0U || serialized[i - 1U] == '\n') &&
            memcmp(serialized + i, field_prefix, prefix_length) == 0) {
            field = serialized + i;
            break;
        }
    }
    if (!field) return NULL;
    value = field + prefix_length;
    newline = memchr(value, '\n',
                     serialized_length - (size_t)(value - serialized));
    if (!newline) return NULL;
    component_start = value;
    for (size_t i = 0; i < component_index; i++) {
        const unsigned char *separator =
            memchr(component_start, ':',
                   (size_t)(newline - component_start));
        if (!separator) return NULL;
        component_start = separator + 1U;
    }
    component_end = memchr(component_start, ':',
                           (size_t)(newline - component_start));
    if (!component_end) component_end = newline;
    before_length = (size_t)(component_start - serialized);
    after_length = serialized_length -
                   (size_t)(component_end - serialized);
    if (before_length > PUBLICATION_LEDGER_MAX_BYTES ||
        replacement_length >
            PUBLICATION_LEDGER_MAX_BYTES - before_length ||
        after_length > PUBLICATION_LEDGER_MAX_BYTES -
                           before_length - replacement_length) {
        return NULL;
    }
    *replaced_length = before_length + replacement_length + after_length;
    replaced = malloc(*replaced_length);
    if (!replaced) {
        *replaced_length = 0U;
        return NULL;
    }
    memcpy(replaced, serialized, before_length);
    memcpy(replaced + before_length, replacement, replacement_length);
    memcpy(replaced + before_length + replacement_length, component_end,
           after_length);
    return replaced;
}

static size_t find_serialized_bytes(const unsigned char *data, size_t length,
                                    const char *needle) {
    size_t needle_length = needle ? strlen(needle) : 0U;

    if (!data || needle_length == 0U || needle_length > length) {
        return SIZE_MAX;
    }
    for (size_t i = 0; i + needle_length <= length; i++) {
        if (memcmp(data + i, needle, needle_length) == 0) return i;
    }
    return SIZE_MAX;
}

static unsigned char *replace_serialized_field_value(
    const unsigned char *data, size_t length, const char *prefix,
    const char *replacement, size_t *replaced_length) {
    size_t field_offset;
    size_t prefix_length;
    size_t value_offset;
    size_t newline_offset;
    size_t replacement_length;
    unsigned char *replaced;

    if (!data || !prefix || !replacement || !replaced_length) return NULL;
    *replaced_length = 0U;
    field_offset = find_serialized_bytes(data, length, prefix);
    if (field_offset == SIZE_MAX) return NULL;
    prefix_length = strlen(prefix);
    value_offset = field_offset + prefix_length;
    newline_offset = value_offset;
    while (newline_offset < length && data[newline_offset] != '\n') {
        newline_offset++;
    }
    if (newline_offset == length) return NULL;
    replacement_length = strlen(replacement);
    if (value_offset > SIZE_MAX - replacement_length ||
        value_offset + replacement_length >
            SIZE_MAX - (length - newline_offset)) {
        return NULL;
    }
    *replaced_length = value_offset + replacement_length +
                       (length - newline_offset);
    replaced = malloc(*replaced_length);
    if (!replaced) {
        *replaced_length = 0U;
        return NULL;
    }
    memcpy(replaced, data, value_offset);
    memcpy(replaced + value_offset, replacement, replacement_length);
    memcpy(replaced + value_offset + replacement_length,
           data + newline_offset, length - newline_offset);
    return replaced;
}

static unsigned char *remove_serialized_field_line(
    const unsigned char *data, size_t length, const char *prefix,
    size_t *replaced_length) {
    size_t field_offset;
    size_t newline_offset;
    size_t removed_length;
    unsigned char *replaced;

    if (!data || !prefix || !replaced_length) return NULL;
    *replaced_length = 0U;
    field_offset = find_serialized_bytes(data, length, prefix);
    if (field_offset == SIZE_MAX ||
        (field_offset != 0U && data[field_offset - 1U] != '\n')) {
        return NULL;
    }
    newline_offset = field_offset;
    while (newline_offset < length && data[newline_offset] != '\n') {
        newline_offset++;
    }
    if (newline_offset == length) return NULL;
    removed_length = newline_offset + 1U - field_offset;
    replaced = malloc(length - removed_length);
    if (!replaced) return NULL;
    memcpy(replaced, data, field_offset);
    memcpy(replaced + field_offset, data + newline_offset + 1U,
           length - newline_offset - 1U);
    *replaced_length = length - removed_length;
    return replaced;
}

static void check_replaced_publication_field_rejected(
    const unsigned char *serialized, size_t serialized_length,
    const char *prefix, const char *replacement) {
    publication_ledger_t parsed;
    unsigned char *corrupted;
    size_t corrupted_length = 0U;

    corrupted = replace_serialized_field_value(
        serialized, serialized_length, prefix, replacement,
        &corrupted_length);
    CHECK(corrupted != NULL);
    publication_ledger_init(&parsed);
    if (corrupted) {
        clear_error();
        CHECK_EQ_INT(publication_ledger_parse(
                         corrupted, corrupted_length, &parsed), -1);
    }
    CHECK(!parsed.present);
    CHECK_EQ_INT((long)parsed.count, 0);
    CHECK(parsed.records == NULL);
    publication_ledger_clear(&parsed);
    free(corrupted);
}

static void check_publication_bytes_rejected(
    const unsigned char *serialized, size_t serialized_length) {
    publication_ledger_t parsed;

    publication_ledger_init(&parsed);
    clear_error();
    CHECK_EQ_INT(publication_ledger_parse(
                     serialized, serialized_length, &parsed), -1);
    CHECK(!parsed.present);
    CHECK_EQ_INT((long)parsed.count, 0);
    CHECK(parsed.records == NULL);
    publication_ledger_clear(&parsed);
}

static void fill_active_context(gitswitch_ctx_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->config.default_scope = GIT_SCOPE_GLOBAL;
    ctx->account_count = 1;
    ctx->accounts[0].id = UINT32_C(41);
    snprintf(ctx->accounts[0].incarnation,
             sizeof(ctx->accounts[0].incarnation), "%s", INCARNATION_A);
    ctx->accounts[0].incarnation_persisted = true;
    snprintf(ctx->accounts[0].name, sizeof(ctx->accounts[0].name),
             "%s", "alice");
    snprintf(ctx->accounts[0].email, sizeof(ctx->accounts[0].email),
             "%s", "alice@example.test");
    ctx->accounts[0].gpg_enabled = true;
    ctx->accounts[0].gpg_signing_enabled = true;
    /* The account keeps the user selector. Durable identity belongs only in
     * the publication record installed beside the active-state lines. */
    snprintf(ctx->accounts[0].gpg_key_id,
             sizeof(ctx->accounts[0].gpg_key_id), "%s", "22223333");
    snprintf(ctx->config.active_account,
             sizeof(ctx->config.active_account), "%s", "alice");
    ctx->current_account = &ctx->accounts[0];
}

static config_io_boundary_t publication_fault_target;
static int retirement_runner_calls;
static int retirement_unset_attempts;
static bool retirement_signing_key_present;
static char retirement_expected_config_path[MAX_PATH_LEN];
static char retirement_expected_gpg_program[MAX_PATH_LEN];

static bool fail_publication_boundary(config_io_boundary_t boundary) {
    return boundary == publication_fault_target;
}

static int append_retirement_snapshot_record(
    char *buffer, size_t capacity, size_t *used,
    const char *key, const char *value) {
    int written;

    if (!buffer || !used || !key || !value || *used >= capacity) return -1;
    written = snprintf(buffer + *used, capacity - *used,
                       "%s\n%s", key, value);
    if (written < 0 || (size_t)written >= capacity - *used) return -1;
    *used += (size_t)written + 1U;
    return 0;
}

static int count_unexpected_retirement_runner(
    const char *const argv[], const run_opts_t *opts, run_result_t *result) {
    const char *operation;

    retirement_runner_calls++;
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (!argv || !argv[0] || strcmp(argv[0], "git") != 0 || !argv[1] ||
        strcmp(argv[1], "config") != 0 || !argv[2] ||
        strcmp(argv[2], "--file") != 0 || !argv[3] ||
        retirement_expected_config_path[0] == '\0' ||
        strcmp(argv[3], retirement_expected_config_path) != 0 || !argv[4]) {
        if (result) result->exit_code = 2;
        return -1;
    }
    if (strcmp(argv[4], "--list") == 0) {
        size_t used = 0U;

        if (!argv[5] || strcmp(argv[5], "-z") != 0 || !argv[6] ||
            strcmp(argv[6], "--no-includes") != 0 || argv[7] ||
            !opts || !opts->out) {
            if (result) result->exit_code = 2;
            return -1;
        }
        if (retirement_signing_key_present) {
            if (append_retirement_snapshot_record(
                    opts->out, opts->out_size, &used,
                    "user.signingkey", FINGERPRINT_A) != 0 ||
                append_retirement_snapshot_record(
                    opts->out, opts->out_size, &used,
                    "commit.gpgsign", "true") != 0 ||
                append_retirement_snapshot_record(
                    opts->out, opts->out_size, &used,
                    "gpg.format", "openpgp") != 0 ||
                append_retirement_snapshot_record(
                    opts->out, opts->out_size, &used,
                    "gpg.openpgp.program",
                    retirement_expected_gpg_program) != 0) {
                if (result) result->exit_code = 2;
                return -1;
            }
            if (result) result->out_len = used;
        } else {
            opts->out[0] = '\0';
        }
        if (result) result->exit_code = 0;
        return 0;
    }
    if (strcmp(argv[4], "--no-includes") != 0 || !argv[5] ||
        strcmp(argv[5], "--fixed-value") != 0 || !argv[6] ||
        !argv[7] || !argv[8] || argv[9]) {
        if (result) result->exit_code = 2;
        return -1;
    }
    operation = argv[6];
    if (strcmp(operation, "--unset-all") == 0) {
        retirement_unset_attempts++;
        /* Inject a pre-mutation Git failure: the modeled key remains present. */
        if (result) result->exit_code = 2;
        return -1;
    }
    if (result) result->exit_code = 1;
    return -1;
}

static int create_complete_global_publication(
    publication_record_t *record, uint32_t account_id,
    const char *account_incarnation,
    const char *parent_path, const char *config_path) {
    char program[MAX_PATH_LEN];
    struct stat st;
    int fd;
    static const char contents[] = "[fixture]\n";

    fd = open(config_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (write(fd, contents, sizeof(contents) - 1U) !=
        (ssize_t)(sizeof(contents) - 1U)) {
        close(fd);
        return -1;
    }
    if (close(fd) != 0) return -1;
    publication_record_init(record);
    record->account_id = account_id;
    if (snprintf(record->account_incarnation,
                 sizeof(record->account_incarnation), "%s",
                 account_incarnation) >=
        (int)sizeof(record->account_incarnation)) {
        return -1;
    }
    record->scope = PUBLICATION_SCOPE_GLOBAL;
    if (!realpath(config_path, record->config_path) ||
        stat(parent_path, &st) != 0) {
        return -1;
    }
    publication_identity_from_stat(&record->config_parent, &st);
    if (stat(record->config_path, &st) != 0) return -1;
    publication_identity_from_stat(&record->post_config, &st);
    record->capabilities = PUBLICATION_CAP_DESTINATION |
                           PUBLICATION_CAP_POST_GENERATION |
                           PUBLICATION_CAP_GPG_FINGERPRINT |
                           PUBLICATION_CAP_GPG_PROGRAM |
                           PUBLICATION_CAP_GPG_SELECTOR;
    snprintf(record->gpg_fingerprint, sizeof(record->gpg_fingerprint), "%s",
             FINGERPRINT_A);
    snprintf(record->gpg_selector, sizeof(record->gpg_selector), "%s",
             SELECTOR_A);
    if (!realpath("/bin/sh", program) ||
        snprintf(record->gpg_program, sizeof(record->gpg_program), "%s",
                 program) >= (int)sizeof(record->gpg_program) ||
        stat(record->gpg_program, &st) != 0) {
        return -1;
    }
    publication_identity_from_stat(&record->gpg_program_identity, &st);
    record->state = PUBLICATION_STATE_PUBLISHED;
    return publication_record_validate(record);
}

static int bind_live_local_destination(publication_record_t *record,
                                       const char *repository_path,
                                       const char *config_parent_path,
                                       const char *config_path) {
    struct stat st;

    if (!record || !repository_path || !config_parent_path || !config_path ||
        snprintf(record->repository_path, sizeof(record->repository_path),
                 "%s", repository_path) >=
            (int)sizeof(record->repository_path) ||
        snprintf(record->config_path, sizeof(record->config_path), "%s",
                 config_path) >= (int)sizeof(record->config_path) ||
        stat(repository_path, &st) != 0) {
        return -1;
    }
    publication_identity_from_stat(&record->repository, &st);
    if (stat(config_parent_path, &st) != 0) return -1;
    publication_identity_from_stat(&record->config_parent, &st);
    if (stat(config_path, &st) != 0) return -1;
    publication_identity_from_stat(&record->post_config, &st);
    return publication_record_validate(record);
}

static int encode_upper_hex(const char *value, char *out, size_t out_size) {
    static const char digits[] = "0123456789ABCDEF";
    size_t length;

    if (!value || !out ||
        (length = strlen(value)) > (out_size - 1U) / 2U) {
        return -1;
    }
    for (size_t i = 0U; i < length; i++) {
        unsigned char byte = (unsigned char)value[i];
        out[i * 2U] = digits[byte >> 4U];
        out[i * 2U + 1U] = digits[byte & 0x0fU];
    }
    out[length * 2U] = '\0';
    return 0;
}

static void check_record_identity(const publication_record_t *record,
                                  const char *repository_path,
                                  const char *fingerprint) {
    CHECK(record != NULL);
    if (!record) return;
    CHECK_EQ_INT((int)record->account_id, 41);
    CHECK_STR_EQ(record->account_incarnation, INCARNATION_A);
    CHECK_EQ_INT((int)record->scope, (int)PUBLICATION_SCOPE_LOCAL);
    CHECK_STR_EQ(record->config_path,
                 "/tmp/ar11-publication/repository/.git/config");
    CHECK_STR_EQ(record->repository_path, repository_path);
    CHECK_EQ_INT((int)record->capabilities,
                 (int)(PUBLICATION_CAP_DESTINATION |
                       PUBLICATION_CAP_POST_GENERATION |
                       PUBLICATION_CAP_GPG_FINGERPRINT |
                       PUBLICATION_CAP_GPG_PROGRAM |
                       PUBLICATION_CAP_GPG_SELECTOR));
    CHECK_STR_EQ(record->gpg_fingerprint, fingerprint);
    CHECK_STR_EQ(record->gpg_selector, SELECTOR_A);
    CHECK_STR_EQ(record->gpg_program, "/usr/bin/gpg");
    CHECK(record->gpg_program_identity.present);
    CHECK_EQ_INT((long)record->gpg_program_identity.inode, 104);
    CHECK_EQ_INT((int)record->state, (int)PUBLICATION_STATE_PUBLISHED);
    CHECK(record->config_parent.present);
    CHECK(record->repository.present);
    CHECK(record->post_config.present);
    CHECK_EQ_INT((long)record->post_config.inode, 103);
    CHECK_EQ_INT((long)record->post_config.size, 211);
    CHECK_EQ_INT((long)record->post_config.ctime_seconds,
                 (long)(INT64_C(1722000000) + INT64_C(103)));
    CHECK_EQ_INT((long)record->post_config.ctime_nanoseconds,
                 (long)UINT32_C(987654321));
}

TEST(empty_tail_is_an_explicit_legacy_ledger_absence) {
    publication_ledger_t ledger;
    static const unsigned char empty[] = "";

    publication_ledger_init(&ledger);
    CHECK_EQ_INT(publication_ledger_parse(empty, 0, &ledger), 0);
    CHECK(!ledger.present);
    CHECK_EQ_INT((int)ledger.version, 0);
    CHECK_EQ_INT((int)ledger.count, 0);
    CHECK(ledger.records == NULL);
    publication_ledger_clear(&ledger);
}

TEST(gpg_selector_normalization_canonicalizes_case_prefix_and_v5_boundary) {
    char normalized[MAX_GPG_SELECTOR_LEN];
    char prefixed_64[MAX_GPG_SELECTOR_LEN];
    char oversized[66];
    char prefixed_oversized[68];

    CHECK_EQ_INT(publication_normalize_gpg_selector(
                     "deadBEEF", normalized), 0);
    CHECK_STR_EQ(normalized, "DEADBEEF");
    CHECK_EQ_INT(publication_normalize_gpg_selector(
                     "0xdeadBEEF", normalized), 0);
    CHECK_STR_EQ(normalized, "DEADBEEF");
    CHECK_EQ_INT(publication_normalize_gpg_selector(
                     "0XAbCd0123", normalized), 0);
    CHECK_STR_EQ(normalized, "ABCD0123");

    CHECK_EQ_INT((long)strlen(SELECTOR_64), 64);
    CHECK_EQ_INT(snprintf(prefixed_64, sizeof(prefixed_64), "0x%s",
                          SELECTOR_64), 66);
    CHECK_EQ_INT(publication_normalize_gpg_selector(
                     prefixed_64, normalized), 0);
    CHECK_EQ_INT((long)strlen(normalized), 64);
    CHECK_STR_EQ(normalized, SELECTOR_64);

    memset(oversized, 'A', sizeof(oversized) - 1U);
    oversized[sizeof(oversized) - 1U] = '\0';
    CHECK_EQ_INT((long)strlen(oversized), 65);
    CHECK_EQ_INT(snprintf(prefixed_oversized,
                          sizeof(prefixed_oversized), "0x%s", oversized), 67);

    memset(normalized, 'X', sizeof(normalized));
    CHECK_EQ_INT(publication_normalize_gpg_selector(NULL, normalized), -1);
    CHECK_STR_EQ(normalized, "");
    CHECK_EQ_INT(publication_normalize_gpg_selector("", normalized), -1);
    CHECK_STR_EQ(normalized, "");
    CHECK_EQ_INT(publication_normalize_gpg_selector("0x", normalized), -1);
    CHECK_STR_EQ(normalized, "");
    CHECK_EQ_INT(publication_normalize_gpg_selector(
                     "DEADBEEG", normalized), -1);
    CHECK_STR_EQ(normalized, "");
    CHECK_EQ_INT(publication_normalize_gpg_selector(
                     "DEAD\xC0\xAF", normalized), -1);
    CHECK_STR_EQ(normalized, "");
    CHECK_EQ_INT(publication_normalize_gpg_selector(
                     oversized, normalized), -1);
    CHECK_STR_EQ(normalized, "");
    CHECK_EQ_INT(publication_normalize_gpg_selector(
                     prefixed_oversized, normalized), -1);
    CHECK_STR_EQ(normalized, "");
    CHECK_EQ_INT(publication_normalize_gpg_selector("A", NULL), -1);
}

TEST(gpg_selector_record_validation_requires_complete_canonical_tuple) {
    static const uint32_t malformed_gpg_masks[] = {
        PUBLICATION_CAP_GPG_FINGERPRINT,
        PUBLICATION_CAP_GPG_PROGRAM,
        PUBLICATION_CAP_GPG_SELECTOR,
        PUBLICATION_CAP_GPG_FINGERPRINT | PUBLICATION_CAP_GPG_SELECTOR,
        PUBLICATION_CAP_GPG_PROGRAM | PUBLICATION_CAP_GPG_SELECTOR
    };
    static const char *const malformed_selectors[] = {
        "", "deadbeef", "0xDEADBEEF", "DEADBEEG", "-"
    };
    publication_record_t record;
    publication_record_t candidate;
    char oversized[66];

    fill_gpg_record(&record, "/tmp/ar11-publication/repository",
                    FINGERPRINT_A);
    CHECK_EQ_INT(publication_record_validate(&record), 0);

    candidate = record;
    snprintf(candidate.gpg_selector, sizeof(candidate.gpg_selector), "%s",
             SELECTOR_64);
    CHECK_EQ_INT(publication_record_validate(&candidate), 0);

    /* The pre-selector fingerprint/program pair remains a valid retirement
     * witness. A selector alone, or paired with only one witness, never is. */
    candidate = record;
    candidate.capabilities &= ~PUBLICATION_CAP_GPG_SELECTOR;
    candidate.gpg_selector[0] = '\0';
    candidate.state = PUBLICATION_STATE_RETIRING;
    CHECK_EQ_INT(publication_record_validate(&candidate), 0);

    for (size_t i = 0U;
         i < sizeof(malformed_gpg_masks) / sizeof(malformed_gpg_masks[0]);
         i++) {
        candidate = record;
        candidate.capabilities = PUBLICATION_CAP_DESTINATION |
                                 PUBLICATION_CAP_POST_GENERATION |
                                 malformed_gpg_masks[i];
        clear_error();
        CHECK_EQ_INT(publication_record_validate(&candidate), -1);
        CHECK(strstr(get_last_error()->message,
                     "Incomplete publication GPG provenance tuple") != NULL);
    }

    candidate = record;
    candidate.capabilities &= ~PUBLICATION_CAP_POST_GENERATION;
    clear_error();
    CHECK_EQ_INT(publication_record_validate(&candidate), -1);
    CHECK(strstr(get_last_error()->message,
                 "requires a post-config generation") != NULL);

    for (size_t i = 0U;
         i < sizeof(malformed_selectors) / sizeof(malformed_selectors[0]);
         i++) {
        candidate = record;
        snprintf(candidate.gpg_selector, sizeof(candidate.gpg_selector),
                 "%s", malformed_selectors[i]);
        clear_error();
        CHECK_EQ_INT(publication_record_validate(&candidate), -1);
        CHECK(strstr(get_last_error()->message,
                     "selector is not canonical uppercase hex") != NULL);
    }

    memset(oversized, 'A', sizeof(oversized) - 1U);
    oversized[sizeof(oversized) - 1U] = '\0';
    candidate = record;
    snprintf(candidate.gpg_selector, sizeof(candidate.gpg_selector), "%s",
             oversized);
    clear_error();
    CHECK_EQ_INT(publication_record_validate(&candidate), -1);
    CHECK(strstr(get_last_error()->message,
                 "selector is not canonical uppercase hex") != NULL);

    candidate = record;
    candidate.capabilities &= ~PUBLICATION_CAP_GPG_SELECTOR;
    clear_error();
    CHECK_EQ_INT(publication_record_validate(&candidate), -1);
    CHECK(strstr(get_last_error()->message,
                 "selector lacks its capability bit") != NULL);

    candidate = record;
    memset(candidate.gpg_selector, 'A', sizeof(candidate.gpg_selector));
    clear_error();
    CHECK_EQ_INT(publication_record_validate(&candidate), -1);
    CHECK(strstr(get_last_error()->message,
                 "Unterminated publication record field") != NULL);
}

TEST(ssh_program_extraction_accepts_only_the_managed_first_word) {
    static const char escaped_command[] =
        "'/opt/ssh'\\''helper' -i '/tmp/key' -F '/dev/null'";
    char program[MAX_PATH_LEN];
    char tiny[4];

    CHECK_EQ_INT(publication_extract_ssh_program(
                     SSH_COMMAND_A, program, sizeof(program)), 0);
    CHECK_STR_EQ(program, SSH_PROGRAM_A);
    CHECK_EQ_INT(publication_extract_ssh_program(
                     escaped_command, program, sizeof(program)), 0);
    CHECK_STR_EQ(program, "/opt/ssh'helper");

    CHECK_EQ_INT(publication_extract_ssh_program(
                     "/usr/bin/ssh -i '/tmp/key'", program,
                     sizeof(program)), -1);
    CHECK_EQ_INT(publication_extract_ssh_program(
                     "'ssh' -i '/tmp/key'", program,
                     sizeof(program)), -1);
    CHECK_EQ_INT(publication_extract_ssh_program(
                     "'/usr/bin/ssh' -F '/dev/null'", program,
                     sizeof(program)), -1);
    CHECK_EQ_INT(publication_extract_ssh_program(
                     "'/usr/bin/ssh -i '/tmp/key'", program,
                     sizeof(program)), -1);
    CHECK_EQ_INT(publication_extract_ssh_program(
                     "'/usr/bin/ssh\n' -i '/tmp/key'", program,
                     sizeof(program)), -1);
    CHECK_EQ_INT(publication_extract_ssh_program(
                     SSH_COMMAND_A, tiny, sizeof(tiny)), -1);
    CHECK_EQ_INT(publication_extract_ssh_program(
                     NULL, program, sizeof(program)), -1);
    CHECK_EQ_INT(publication_extract_ssh_program(
                     SSH_COMMAND_A, NULL, 0U), -1);
}

TEST(ssh_record_validation_requires_complete_matching_provenance) {
    static const uint32_t incomplete_masks[] = {
        PUBLICATION_CAP_SSH_COMMAND,
        PUBLICATION_CAP_SSH_PROGRAM
    };
    publication_record_t record;
    publication_record_t candidate;

    fill_ssh_record(&record);
    CHECK_EQ_INT(publication_record_validate(&record), 0);

    for (size_t i = 0U;
         i < sizeof(incomplete_masks) / sizeof(incomplete_masks[0]); i++) {
        candidate = record;
        candidate.capabilities = PUBLICATION_CAP_DESTINATION |
                                 PUBLICATION_CAP_POST_GENERATION |
                                 incomplete_masks[i];
        clear_error();
        CHECK_EQ_INT(publication_record_validate(&candidate), -1);
        CHECK(strstr(get_last_error()->message,
                     "Incomplete publication SSH provenance tuple") != NULL);
    }

    candidate = record;
    candidate.capabilities &= ~PUBLICATION_CAP_POST_GENERATION;
    memset(&candidate.post_config, 0, sizeof(candidate.post_config));
    clear_error();
    CHECK_EQ_INT(publication_record_validate(&candidate), -1);
    CHECK(strstr(get_last_error()->message,
                 "SSH provenance requires a post-config generation") !=
          NULL);

    candidate = record;
    CHECK_EQ_INT(safe_strncpy(candidate.ssh_program, SSH_PROGRAM_B,
                              sizeof(candidate.ssh_program)), 0);
    clear_error();
    CHECK_EQ_INT(publication_record_validate(&candidate), -1);
    CHECK(strstr(get_last_error()->message,
                 "SSH command executable does not match its persisted program") !=
          NULL);

    candidate = record;
    CHECK_EQ_INT(safe_strncpy(candidate.ssh_command,
                              "/usr/bin/ssh -i '/tmp/key'",
                              sizeof(candidate.ssh_command)), 0);
    CHECK_EQ_INT(publication_record_validate(&candidate), -1);

    candidate = record;
    candidate.capabilities &= ~(PUBLICATION_CAP_SSH_COMMAND |
                                PUBLICATION_CAP_SSH_PROGRAM);
    clear_error();
    CHECK_EQ_INT(publication_record_validate(&candidate), -1);
    CHECK(strstr(get_last_error()->message,
                 "SSH command lacks its capability bit") != NULL);

    candidate = record;
    candidate.ssh_command[0] = '\0';
    CHECK_EQ_INT(publication_record_validate(&candidate), -1);

    candidate = record;
    candidate.ssh_program[0] = '\0';
    CHECK_EQ_INT(publication_record_validate(&candidate), -1);

    candidate = record;
    candidate.ssh_program[0] = 's';
    CHECK_EQ_INT(publication_record_validate(&candidate), -1);

    candidate = record;
    candidate.ssh_program_identity.mode = (uintmax_t)(S_IFDIR | 0755);
    CHECK_EQ_INT(publication_record_validate(&candidate), -1);
}

TEST(complete_ssh_tuple_round_trip_preserves_exact_record) {
    static const char capabilities_prefix[] = "p.0.capabilities=";
    static const char command_prefix[] = "p.0.ssh_command=";
    static const char program_prefix[] = "p.0.ssh_program=";
    publication_record_t record;
    publication_ledger_t source;
    publication_ledger_t loaded;
    const publication_record_t *found = NULL;
    unsigned char *serialized = NULL;
    size_t serialized_length = 0U;

    fill_ssh_record(&record);
    publication_ledger_init(&source);
    publication_ledger_init(&loaded);
    CHECK_EQ_INT(publication_ledger_upsert(&source, &record), 0);
    CHECK_EQ_INT(publication_ledger_serialize(
                     &source, &serialized, &serialized_length), 0);
    CHECK(serialized != NULL);
    CHECK(find_serialized_bytes(serialized, serialized_length,
                                command_prefix) != SIZE_MAX);
    CHECK(find_serialized_bytes(serialized, serialized_length,
                                program_prefix) != SIZE_MAX);
    if (serialized) {
        CHECK_EQ_INT(publication_ledger_parse(
                         serialized, serialized_length, &loaded), 0);
    }
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &loaded, UINT32_C(41), INCARNATION_A,
                     PUBLICATION_SCOPE_LOCAL,
                     "/tmp/ar11-publication/repository/.git/config",
                     "/tmp/ar11-publication/repository", &found),
                 PUBLICATION_LOOKUP_FOUND);
    CHECK(found != NULL);
    if (found) {
        CHECK_EQ_INT((int)(found->capabilities &
                           (PUBLICATION_CAP_SSH_COMMAND |
                            PUBLICATION_CAP_SSH_PROGRAM)),
                     (int)(PUBLICATION_CAP_SSH_COMMAND |
                           PUBLICATION_CAP_SSH_PROGRAM));
        CHECK_STR_EQ(found->ssh_command, SSH_COMMAND_A);
        CHECK_STR_EQ(found->ssh_program, SSH_PROGRAM_A);
        CHECK(publication_identity_equal(&found->ssh_program_identity,
                                         &record.ssh_program_identity));
    }

    check_replaced_publication_field_rejected(
        serialized, serialized_length, capabilities_prefix, "00000013");
    check_replaced_publication_field_rejected(
        serialized, serialized_length, capabilities_prefix, "00000023");
    check_replaced_publication_field_rejected(
        serialized, serialized_length, capabilities_prefix, "00000031");
    check_replaced_publication_field_rejected(
        serialized, serialized_length, command_prefix, "");
    /* /usr/bin/scp is well-formed hex and an absolute path, but it is not the
     * executable sealed in SSH_COMMAND_A. */
    check_replaced_publication_field_rejected(
        serialized, serialized_length, program_prefix,
        "2F7573722F62696E2F736370");

    free(serialized);
    publication_ledger_clear(&loaded);
    publication_ledger_clear(&source);
}

TEST(complete_gpg_selector_tuple_round_trip_preserves_exact_record) {
    publication_record_t record;
    publication_ledger_t source;
    publication_ledger_t loaded;
    const publication_record_t *found;
    unsigned char *serialized = NULL;
    size_t serialized_length = 0;

    fill_gpg_record(&record, "/tmp/ar11-publication/repository",
                    FINGERPRINT_A);
    {
        publication_identity_t rewritten = record.post_config;
        rewritten.ctime_nanoseconds--;
        CHECK(!publication_identity_equal(&record.post_config, &rewritten));
    }
    publication_ledger_init(&source);
    publication_ledger_init(&loaded);

    CHECK_EQ_INT(publication_record_validate(&record), 0);
    CHECK_EQ_INT(publication_ledger_upsert(&source, &record), 0);
    CHECK(source.present);
    CHECK_EQ_INT((int)source.version, (int)PUBLICATION_LEDGER_VERSION);
    CHECK_EQ_INT((int)source.count, 1);
    CHECK_EQ_INT(publication_ledger_serialize(
                     &source, &serialized, &serialized_length), 0);
    CHECK(serialized != NULL);
    CHECK(serialized_length > 0);
    CHECK(find_serialized_bytes(serialized, serialized_length,
                                "p.0.gpg_selector=" SELECTOR_A "\n") !=
          SIZE_MAX);

    if (serialized) {
        CHECK_EQ_INT(publication_ledger_parse(
                         serialized, serialized_length, &loaded), 0);
    }
    CHECK(loaded.present);
    CHECK_EQ_INT((int)loaded.version, (int)PUBLICATION_LEDGER_VERSION);
    CHECK_EQ_INT((int)loaded.count, 1);
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &loaded, UINT32_C(41), INCARNATION_A,
                     PUBLICATION_SCOPE_LOCAL,
                     "/tmp/ar11-publication/repository/.git/config",
                     "/tmp/ar11-publication/repository", &found),
                 PUBLICATION_LOOKUP_FOUND);
    check_record_identity(found, "/tmp/ar11-publication/repository",
                          FINGERPRINT_A);

    free(serialized);
    publication_ledger_clear(&loaded);
    publication_ledger_clear(&source);
}

TEST(legacy_gpg_pair_without_selector_field_remains_retirement_compatible) {
    static const char selector_prefix[] = "p.0.gpg_selector=";
    publication_record_t record;
    publication_ledger_t source;
    publication_ledger_t loaded;
    const publication_record_t *found = NULL;
    unsigned char *serialized = NULL;
    unsigned char *legacy = NULL;
    unsigned char *reserialized = NULL;
    size_t serialized_length = 0U;
    size_t legacy_length = 0U;
    size_t reserialized_length = 0U;

    fill_gpg_record(&record, "/tmp/ar11-publication/repository",
                    FINGERPRINT_A);
    record.capabilities &= ~PUBLICATION_CAP_GPG_SELECTOR;
    record.gpg_selector[0] = '\0';
    record.state = PUBLICATION_STATE_RETIRING;
    CHECK_EQ_INT(publication_record_validate(&record), 0);

    publication_ledger_init(&source);
    publication_ledger_init(&loaded);
    CHECK_EQ_INT(publication_ledger_upsert(&source, &record), 0);
    CHECK_EQ_INT(publication_ledger_serialize(
                     &source, &serialized, &serialized_length), 0);
    CHECK(find_serialized_bytes(serialized, serialized_length,
                                "p.0.gpg_selector=-\n") != SIZE_MAX);

    legacy = remove_serialized_field_line(
        serialized, serialized_length, selector_prefix, &legacy_length);
    CHECK(legacy != NULL);
    CHECK(legacy_length < serialized_length);
    if (legacy) {
        CHECK_EQ_INT(publication_ledger_parse(
                         legacy, legacy_length, &loaded), 0);
    }
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &loaded, UINT32_C(41), INCARNATION_A,
                     PUBLICATION_SCOPE_LOCAL,
                     "/tmp/ar11-publication/repository/.git/config",
                     "/tmp/ar11-publication/repository", &found),
                 PUBLICATION_LOOKUP_FOUND);
    CHECK(found != NULL);
    if (found) {
        CHECK_EQ_INT((int)(found->capabilities &
                           (PUBLICATION_CAP_GPG_FINGERPRINT |
                            PUBLICATION_CAP_GPG_PROGRAM |
                            PUBLICATION_CAP_GPG_SELECTOR)),
                     (int)(PUBLICATION_CAP_GPG_FINGERPRINT |
                           PUBLICATION_CAP_GPG_PROGRAM));
        CHECK_STR_EQ(found->gpg_fingerprint, FINGERPRINT_A);
        CHECK_STR_EQ(found->gpg_selector, "");
        CHECK_STR_EQ(found->gpg_program, "/usr/bin/gpg");
        CHECK_EQ_INT((int)found->state,
                     (int)PUBLICATION_STATE_RETIRING);
        CHECK_EQ_INT(publication_record_validate(found), 0);
    }

    /* Once loaded, the compatibility record reserializes in the canonical
     * current grammar with an explicit absent-selector marker. */
    CHECK_EQ_INT(publication_ledger_serialize(
                     &loaded, &reserialized, &reserialized_length), 0);
    CHECK(find_serialized_bytes(reserialized, reserialized_length,
                                "p.0.gpg_selector=-\n") != SIZE_MAX);

    free(reserialized);
    free(legacy);
    free(serialized);
    publication_ledger_clear(&loaded);
    publication_ledger_clear(&source);
}

TEST(gpg_signing_state_true_and_false_round_trip_canonically) {
    static const bool states[] = {true, false};
    publication_record_t record;

    for (size_t i = 0U; i < sizeof(states) / sizeof(states[0]); i++) {
        publication_ledger_t source;
        publication_ledger_t loaded;
        const publication_record_t *found = NULL;
        unsigned char *serialized = NULL;
        unsigned char *reserialized = NULL;
        size_t serialized_length = 0U;
        size_t reserialized_length = 0U;
        size_t program_identity_offset;
        size_t signing_state_offset;
        size_t ssh_command_offset;
        const char *expected_field = states[i]
            ? "p.0.gpg_signing_enabled=true\n"
            : "p.0.gpg_signing_enabled=false\n";

        fill_gpg_record(&record, "/tmp/ar11-publication/repository",
                        FINGERPRINT_A);
        record.capabilities |= PUBLICATION_CAP_GPG_SIGNING_STATE;
        record.gpg_signing_enabled = states[i];
        publication_ledger_init(&source);
        publication_ledger_init(&loaded);

        CHECK_EQ_INT(publication_record_validate(&record), 0);
        CHECK_EQ_INT(publication_ledger_upsert(&source, &record), 0);
        CHECK_EQ_INT(publication_ledger_serialize(
                         &source, &serialized, &serialized_length), 0);
        CHECK(serialized != NULL);
        program_identity_offset = find_serialized_bytes(
            serialized, serialized_length, "p.0.gpg_program_identity=");
        signing_state_offset = find_serialized_bytes(
            serialized, serialized_length, expected_field);
        ssh_command_offset = find_serialized_bytes(
            serialized, serialized_length, "p.0.ssh_command=");
        CHECK(program_identity_offset != SIZE_MAX);
        CHECK(signing_state_offset != SIZE_MAX);
        CHECK(ssh_command_offset != SIZE_MAX);
        CHECK(program_identity_offset < signing_state_offset);
        CHECK(signing_state_offset < ssh_command_offset);

        if (serialized) {
            CHECK_EQ_INT(publication_ledger_parse(
                             serialized, serialized_length, &loaded), 0);
        }
        CHECK_LOOKUP_STATUS(publication_ledger_find(
                         &loaded, UINT32_C(41), INCARNATION_A,
                         PUBLICATION_SCOPE_LOCAL,
                         "/tmp/ar11-publication/repository/.git/config",
                         "/tmp/ar11-publication/repository", &found),
                     PUBLICATION_LOOKUP_FOUND);
        CHECK(found != NULL);
        if (found) {
            CHECK((found->capabilities &
                   PUBLICATION_CAP_GPG_SIGNING_STATE) != 0U);
            CHECK(found->gpg_signing_enabled == states[i]);
        }

        CHECK_EQ_INT(publication_ledger_serialize(
                         &loaded, &reserialized, &reserialized_length), 0);
        CHECK_EQ_INT((long)reserialized_length, (long)serialized_length);
        if (serialized && reserialized &&
            serialized_length == reserialized_length) {
            CHECK(memcmp(serialized, reserialized, serialized_length) == 0);
        }

        free(reserialized);
        free(serialized);
        publication_ledger_clear(&loaded);
        publication_ledger_clear(&source);
    }
}

TEST(legacy_gpg_signing_state_absence_remains_compatible) {
    static const char signing_state_prefix[] =
        "p.0.gpg_signing_enabled=";
    publication_record_t record;
    publication_ledger_t source;
    publication_ledger_t loaded;
    const publication_record_t *found = NULL;
    unsigned char *serialized = NULL;
    unsigned char *reserialized = NULL;
    size_t serialized_length = 0U;
    size_t reserialized_length = 0U;

    fill_gpg_record(&record, "/tmp/ar11-publication/repository",
                    FINGERPRINT_A);
    CHECK((record.capabilities & PUBLICATION_CAP_GPG_SIGNING_STATE) == 0U);
    CHECK(!record.gpg_signing_enabled);
    CHECK_EQ_INT(publication_record_validate(&record), 0);

    publication_ledger_init(&source);
    publication_ledger_init(&loaded);
    CHECK_EQ_INT(publication_ledger_upsert(&source, &record), 0);
    CHECK_EQ_INT(publication_ledger_serialize(
                     &source, &serialized, &serialized_length), 0);
    CHECK(find_serialized_bytes(serialized, serialized_length,
                                signing_state_prefix) == SIZE_MAX);
    if (serialized) {
        CHECK_EQ_INT(publication_ledger_parse(
                         serialized, serialized_length, &loaded), 0);
    }
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &loaded, UINT32_C(41), INCARNATION_A,
                     PUBLICATION_SCOPE_LOCAL,
                     "/tmp/ar11-publication/repository/.git/config",
                     "/tmp/ar11-publication/repository", &found),
                 PUBLICATION_LOOKUP_FOUND);
    CHECK(found != NULL);
    if (found) {
        CHECK((found->capabilities &
               PUBLICATION_CAP_GPG_SIGNING_STATE) == 0U);
        CHECK(!found->gpg_signing_enabled);
        CHECK_EQ_INT(publication_record_validate(found), 0);
    }

    CHECK_EQ_INT(publication_ledger_serialize(
                     &loaded, &reserialized, &reserialized_length), 0);
    CHECK(find_serialized_bytes(reserialized, reserialized_length,
                                signing_state_prefix) == SIZE_MAX);
    CHECK_EQ_INT((long)reserialized_length, (long)serialized_length);
    if (serialized && reserialized &&
        serialized_length == reserialized_length) {
        CHECK(memcmp(serialized, reserialized, serialized_length) == 0);
    }

    free(reserialized);
    free(serialized);
    publication_ledger_clear(&loaded);
    publication_ledger_clear(&source);
}

TEST(gpg_signing_state_validation_requires_capability_and_gpg_witnesses) {
    publication_record_t record;
    publication_record_t candidate;

    fill_gpg_record(&record, "/tmp/ar11-publication/repository",
                    FINGERPRINT_A);

    candidate = record;
    candidate.gpg_signing_enabled = true;
    clear_error();
    CHECK_EQ_INT(publication_record_validate(&candidate), -1);
    CHECK(strstr(get_last_error()->message,
                 "signing state lacks its capability bit") != NULL);

    fill_ssh_record(&candidate);
    candidate.capabilities |= PUBLICATION_CAP_GPG_SIGNING_STATE;
    clear_error();
    CHECK_EQ_INT(publication_record_validate(&candidate), -1);
    CHECK(strstr(get_last_error()->message,
                 "signing state requires complete GPG provenance") != NULL);
}

TEST(persisted_gpg_signing_state_rejects_malformed_fields_and_order) {
    static const char signing_state_prefix[] =
        "p.0.gpg_signing_enabled=";
    static const char capabilities_prefix[] = "p.0.capabilities=";
    static const char gpg_program_prefix[] = "p.0.gpg_program=";
    static const char *const malformed_tokens[] = {
        "", "TRUE", "False", "1", "yes", "true "
    };
    static const char duplicate_state[] =
        "true\np.0.gpg_signing_enabled=true";
    static const char early_state[] =
        "2F7573722F62696E2F677067\n"
        "p.0.gpg_signing_enabled=true";
    publication_record_t record;
    publication_ledger_t source;
    unsigned char *serialized = NULL;
    unsigned char *without_state = NULL;
    unsigned char *misordered = NULL;
    size_t serialized_length = 0U;
    size_t without_state_length = 0U;
    size_t misordered_length = 0U;

    fill_gpg_record(&record, "/tmp/ar11-publication/repository",
                    FINGERPRINT_A);
    record.capabilities |= PUBLICATION_CAP_GPG_SIGNING_STATE;
    record.gpg_signing_enabled = true;
    publication_ledger_init(&source);
    CHECK_EQ_INT(publication_ledger_upsert(&source, &record), 0);
    CHECK_EQ_INT(publication_ledger_serialize(
                     &source, &serialized, &serialized_length), 0);
    CHECK(find_serialized_bytes(serialized, serialized_length,
                                "p.0.capabilities=000000CF\n") != SIZE_MAX);

    for (size_t i = 0U;
         i < sizeof(malformed_tokens) / sizeof(malformed_tokens[0]); i++) {
        check_replaced_publication_field_rejected(
            serialized, serialized_length, signing_state_prefix,
            malformed_tokens[i]);
    }

    /* A field without its bit, and a bit without its field, are distinct
     * malformed states. The bit also cannot stand in for the GPG witnesses. */
    check_replaced_publication_field_rejected(
        serialized, serialized_length, capabilities_prefix, "0000004F");
    check_replaced_publication_field_rejected(
        serialized, serialized_length, capabilities_prefix, "00000083");

    without_state = remove_serialized_field_line(
        serialized, serialized_length, signing_state_prefix,
        &without_state_length);
    CHECK(without_state != NULL);
    if (without_state) {
        check_publication_bytes_rejected(without_state,
                                         without_state_length);
    }

    check_replaced_publication_field_rejected(
        serialized, serialized_length, signing_state_prefix,
        duplicate_state);

    /* Move the state line before gpg_program_identity. v1 is an ordered
     * grammar, so even a correctly spelled token in the wrong slot fails. */
    if (without_state) {
        misordered = replace_serialized_field_value(
            without_state, without_state_length, gpg_program_prefix,
            early_state, &misordered_length);
    }
    CHECK(misordered != NULL);
    if (misordered) {
        check_publication_bytes_rejected(misordered, misordered_length);
    }

    free(misordered);
    free(without_state);
    free(serialized);
    publication_ledger_clear(&source);
}

TEST(persisted_gpg_selector_schema_rejects_malformed_fields_and_tuples) {
    static const char selector_prefix[] = "p.0.gpg_selector=";
    static const char capabilities_prefix[] = "p.0.capabilities=";
    static const char *const malformed_capabilities[] = {
        "00000007", /* fingerprint only */
        "0000000B", /* program only */
        "00000043", /* selector only */
        "00000047", /* fingerprint + selector */
        "0000004B", /* program + selector */
        "0000004D"  /* complete GPG tuple without post-generation */
    };
    static const char duplicate_selector[] =
        SELECTOR_A "\np.0.gpg_selector=" SELECTOR_A;
    publication_record_t record;
    publication_ledger_t source;
    publication_ledger_t parsed;
    unsigned char *serialized = NULL;
    unsigned char *corrupted = NULL;
    size_t serialized_length = 0U;
    size_t corrupted_length = 0U;
    char overlong[66];
    char oversized_token[68];

    fill_gpg_record(&record, "/tmp/ar11-publication/repository",
                    FINGERPRINT_A);
    publication_ledger_init(&source);
    CHECK_EQ_INT(publication_ledger_upsert(&source, &record), 0);
    CHECK_EQ_INT(publication_ledger_serialize(
                     &source, &serialized, &serialized_length), 0);

    check_replaced_publication_field_rejected(
        serialized, serialized_length, selector_prefix, "");
    check_replaced_publication_field_rejected(
        serialized, serialized_length, selector_prefix, "deadbeef");
    check_replaced_publication_field_rejected(
        serialized, serialized_length, selector_prefix, "0xDEADBEEF");
    check_replaced_publication_field_rejected(
        serialized, serialized_length, selector_prefix, "DEADBEEG");
    check_replaced_publication_field_rejected(
        serialized, serialized_length, selector_prefix, "DEAD\xC0\xAF");

    memset(overlong, 'A', sizeof(overlong) - 1U);
    overlong[sizeof(overlong) - 1U] = '\0';
    check_replaced_publication_field_rejected(
        serialized, serialized_length, selector_prefix, overlong);
    memset(oversized_token, 'A', sizeof(oversized_token) - 1U);
    oversized_token[sizeof(oversized_token) - 1U] = '\0';
    check_replaced_publication_field_rejected(
        serialized, serialized_length, selector_prefix, oversized_token);

    for (size_t i = 0U;
         i < sizeof(malformed_capabilities) /
                 sizeof(malformed_capabilities[0]);
         i++) {
        check_replaced_publication_field_rejected(
            serialized, serialized_length, capabilities_prefix,
            malformed_capabilities[i]);
    }

    /* The selector field is optional only for the exact legacy capability
     * pair. A modern tuple missing it, or any duplicate field, is malformed. */
    corrupted = remove_serialized_field_line(
        serialized, serialized_length, selector_prefix, &corrupted_length);
    CHECK(corrupted != NULL);
    publication_ledger_init(&parsed);
    if (corrupted) {
        CHECK_EQ_INT(publication_ledger_parse(
                         corrupted, corrupted_length, &parsed), -1);
    }
    CHECK(!parsed.present);
    publication_ledger_clear(&parsed);
    free(corrupted);
    corrupted = NULL;

    check_replaced_publication_field_rejected(
        serialized, serialized_length, selector_prefix, duplicate_selector);

    free(serialized);
    publication_ledger_clear(&source);
}

TEST(publication_lookup_distinguishes_absence_from_invalid_or_ambiguous_data) {
    publication_record_t records[2];
    publication_ledger_t ledger;
    const publication_record_t *found = &records[0];

    publication_ledger_init(&ledger);
    clear_error();
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ledger, UINT32_C(41), INCARNATION_A,
                     PUBLICATION_SCOPE_LOCAL,
                     "/tmp/ar11-publication/repository/.git/config",
                     "/tmp/ar11-publication/repository", &found),
                 PUBLICATION_LOOKUP_ABSENT);
    CHECK(found == NULL);

    found = &records[0];
    clear_error();
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ledger, 0U, INCARNATION_A, PUBLICATION_SCOPE_LOCAL,
                     "/tmp/ar11-publication/repository/.git/config",
                     "/tmp/ar11-publication/repository", &found),
                 PUBLICATION_LOOKUP_ERROR);
    CHECK(found == NULL);
    CHECK_EQ_INT((int)get_last_error()->code, (int)ERR_INVALID_ARGS);

    fill_gpg_record(&records[0], "/tmp/ar11-publication/repository",
                    FINGERPRINT_A);
    ledger.present = true;
    ledger.version = PUBLICATION_LEDGER_VERSION;
    ledger.records = records;
    ledger.count = 1U;
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ledger, UINT32_C(41), INCARNATION_A,
                     PUBLICATION_SCOPE_LOCAL,
                     "/tmp/ar11-publication/repository/.git/config",
                     "/tmp/ar11-publication/repository", &found),
                 PUBLICATION_LOOKUP_FOUND);
    CHECK(found == &records[0]);

    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ledger, UINT32_C(42), INCARNATION_A,
                     PUBLICATION_SCOPE_LOCAL,
                     "/tmp/ar11-publication/repository/.git/config",
                     "/tmp/ar11-publication/repository", &found),
                 PUBLICATION_LOOKUP_ABSENT);
    CHECK(found == NULL);

    records[1] = records[0];
    ledger.count = 2U;
    clear_error();
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ledger, UINT32_C(41), INCARNATION_A,
                     PUBLICATION_SCOPE_LOCAL,
                     "/tmp/ar11-publication/repository/.git/config",
                     "/tmp/ar11-publication/repository", &found),
                 PUBLICATION_LOOKUP_ERROR);
    CHECK(found == NULL);
    CHECK(strstr(get_last_error()->message, "duplicate destinations") != NULL);

    /* Distinct object identities are not duplicate destinations, but this
     * path-only query still has two answers and must fail explicitly. */
    records[1].config_parent.inode++;
    clear_error();
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ledger, UINT32_C(41), INCARNATION_A,
                     PUBLICATION_SCOPE_LOCAL,
                     "/tmp/ar11-publication/repository/.git/config",
                     "/tmp/ar11-publication/repository", &found),
                 PUBLICATION_LOOKUP_ERROR);
    CHECK(found == NULL);
    CHECK(strstr(get_last_error()->message, "ambiguous") != NULL);

    records[1].account_id = 0U;
    clear_error();
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ledger, UINT32_C(41), INCARNATION_A,
                     PUBLICATION_SCOPE_LOCAL,
                     "/tmp/ar11-publication/repository/.git/config",
                     "/tmp/ar11-publication/repository", &found),
                 PUBLICATION_LOOKUP_ERROR);
    CHECK(found == NULL);
    CHECK(strstr(get_last_error()->message,
                 "account ID must be nonzero") != NULL);
}

TEST(raw_incarnation_uniformity_includes_skipped_and_rejected_accounts) {
    char longpath[302];
    char source[2048];
    toml_document_t *doc = malloc(sizeof(*doc));

    CHECK(doc != NULL);
    if (!doc) return;
    longpath[0] = '/';
    memset(longpath + 1, 'a', sizeof(longpath) - 2U);
    longpath[sizeof(longpath) - 1U] = '\0';

    CHECK(snprintf(
              source, sizeof(source),
              "[settings]\n"
              "default_scope = \"local\"\n"
              "[accounts.1]\n"
              "incarnation = \"%s\"\n"
              "name = \"bound-but-skipped\"\n"
              "email = \"bound@example.test\"\n"
              "ssh_key = \"%s\"\n"
              "[accounts.2]\n"
              "name = \"legacy\"\n"
              "email = \"legacy@example.test\"\n",
              INCARNATION_A, longpath) < (int)sizeof(source));
    clear_error();
    CHECK_EQ_INT(toml_parse_string(source, strlen(source), doc), -1);
    CHECK(!doc->is_valid);
    CHECK(strstr(get_last_error()->message,
                 "mixes legacy accounts") != NULL);
    toml_cleanup_document(doc);

    CHECK(snprintf(
              source, sizeof(source),
              "[settings]\n"
              "default_scope = \"local\"\n"
              "[accounts.1]\n"
              "incarnation = \"%s\"\n"
              "name = \"bound\"\n"
              "email = \"bound@example.test\"\n"
              "[accounts.2]\n"
              "name = \"legacy-missing-email\"\n",
              INCARNATION_A) < (int)sizeof(source));
    clear_error();
    CHECK_EQ_INT(toml_parse_string(source, strlen(source), doc), -1);
    CHECK(!doc->is_valid);
    CHECK(strstr(get_last_error()->message,
                 "mixes legacy accounts") != NULL);
    toml_cleanup_document(doc);
    free(doc);
}

TEST(publication_parser_requires_one_canonical_account_incarnation) {
    static const char prefix[] = "p.0.incarnation=";
    publication_record_t record;
    publication_ledger_t source;
    publication_ledger_t parsed;
    unsigned char *serialized = NULL;
    unsigned char *corrupted = NULL;
    size_t serialized_length = 0U;
    size_t corrupted_length = 0U;
    size_t field_offset;

    CHECK(account_incarnation_is_valid(INCARNATION_A));
    CHECK(!account_incarnation_is_valid(""));
    CHECK(!account_incarnation_is_valid("1234"));
    CHECK(!account_incarnation_is_valid(
        "a111111111111111111111111111111111111111111111111111111111111111"));

    fill_gpg_record(&record, "/tmp/ar11-publication/repository",
                    FINGERPRINT_A);
    publication_ledger_init(&source);
    CHECK_EQ_INT(publication_ledger_upsert(&source, &record), 0);
    CHECK_EQ_INT(publication_ledger_serialize(
                     &source, &serialized, &serialized_length), 0);
    field_offset = find_serialized_bytes(serialized, serialized_length,
                                         prefix);
    CHECK(field_offset != SIZE_MAX);

    /* Missing the mandatory field: keep the bytes/line count stable while
     * making the parser encounter a different name where incarnation belongs. */
    if (field_offset != SIZE_MAX) {
        corrupted = malloc(serialized_length);
        CHECK(corrupted != NULL);
        if (corrupted) {
            memcpy(corrupted, serialized, serialized_length);
            corrupted[field_offset + sizeof("p.0.") - 1U] = 'X';
            publication_ledger_init(&parsed);
            CHECK_EQ_INT(publication_ledger_parse(
                             corrupted, serialized_length, &parsed), -1);
            publication_ledger_clear(&parsed);
            free(corrupted);
            corrupted = NULL;
        }
    }

    corrupted = replace_serialized_field_value(
        serialized, serialized_length, prefix, "1234", &corrupted_length);
    CHECK(corrupted != NULL);
    if (corrupted) {
        publication_ledger_init(&parsed);
        CHECK_EQ_INT(publication_ledger_parse(
                         corrupted, corrupted_length, &parsed), -1);
        publication_ledger_clear(&parsed);
        free(corrupted);
        corrupted = NULL;
    }

    if (field_offset != SIZE_MAX) {
        corrupted = malloc(serialized_length);
        CHECK(corrupted != NULL);
        if (corrupted) {
            memcpy(corrupted, serialized, serialized_length);
            corrupted[field_offset + strlen(prefix)] = 'a';
            publication_ledger_init(&parsed);
            CHECK_EQ_INT(publication_ledger_parse(
                             corrupted, serialized_length, &parsed), -1);
            publication_ledger_clear(&parsed);
        }
    }

    free(corrupted);
    free(serialized);
    publication_ledger_clear(&source);
}

TEST(identity_parser_rejects_malformed_overflow_and_noncanonical_numbers) {
    static const size_t component_indices[] = {0U, 0U, 7U, 8U, 1U, 7U};
    publication_record_t record;
    publication_ledger_t source;
    publication_ledger_t parsed;
    const publication_record_t *found;
    unsigned char *serialized = NULL;
    size_t serialized_length = 0U;
    char oversized_decimal[64];
    const char *replacements[6];

    memset(oversized_decimal, '9', sizeof(oversized_decimal) - 1U);
    oversized_decimal[sizeof(oversized_decimal) - 1U] = '\0';
    replacements[0] = "";
    replacements[1] = oversized_decimal;
    replacements[2] = oversized_decimal;
    replacements[3] = "1000000000";
    replacements[4] = "01";
    replacements[5] = "+1";

    fill_gpg_record(&record, "/tmp/ar11-publication/repository",
                    FINGERPRINT_A);
    record.config_parent.mtime_seconds = INT64_MIN;
    record.config_parent.ctime_seconds = INT64_MAX;
    publication_ledger_init(&source);
    publication_ledger_init(&parsed);
    CHECK_EQ_INT(publication_ledger_upsert(&source, &record), 0);
    CHECK_EQ_INT(publication_ledger_serialize(
                     &source, &serialized, &serialized_length), 0);

    if (serialized) {
        CHECK_EQ_INT(publication_ledger_parse(
                         serialized, serialized_length, &parsed), 0);
    }
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &parsed, UINT32_C(41), INCARNATION_A,
                     PUBLICATION_SCOPE_LOCAL,
                     "/tmp/ar11-publication/repository/.git/config",
                     "/tmp/ar11-publication/repository", &found),
                 PUBLICATION_LOOKUP_FOUND);
    CHECK(found != NULL);
    if (found) {
        CHECK(found->config_parent.mtime_seconds == INT64_MIN);
        CHECK(found->config_parent.ctime_seconds == INT64_MAX);
    }
    publication_ledger_clear(&parsed);

    for (size_t i = 0; i < sizeof(component_indices) /
                                    sizeof(component_indices[0]); i++) {
        unsigned char *corrupted;
        size_t corrupted_length = 0U;

        corrupted = replace_identity_component(
            serialized, serialized_length, "p.0.config_parent=",
            component_indices[i], replacements[i], &corrupted_length);
        CHECK(corrupted != NULL);
        publication_ledger_init(&parsed);
        if (corrupted) {
            clear_error();
            CHECK_EQ_INT(publication_ledger_parse(
                             corrupted, corrupted_length, &parsed), -1);
        }
        CHECK(!parsed.present);
        CHECK_EQ_INT((int)parsed.count, 0);
        CHECK(parsed.records == NULL);
        publication_ledger_clear(&parsed);
        free(corrupted);
    }

    free(serialized);
    publication_ledger_clear(&source);
}

TEST(serializer_rejects_duplicate_publication_destinations) {
    publication_record_t records[2];
    publication_ledger_t ledger;
    unsigned char *serialized = NULL;
    size_t serialized_length = 0U;

    fill_gpg_record(&records[0], "/tmp/ar11-publication/repository",
                    FINGERPRINT_A);
    records[1] = records[0];
    records[1].account_id = UINT32_C(42);
    snprintf(records[1].gpg_fingerprint,
             sizeof(records[1].gpg_fingerprint), "%s", FINGERPRINT_B);
    publication_ledger_init(&ledger);
    ledger.present = true;
    ledger.version = PUBLICATION_LEDGER_VERSION;
    ledger.records = records;
    ledger.count = 2U;

    clear_error();
    CHECK_EQ_INT(publication_ledger_serialize(
                     &ledger, &serialized, &serialized_length), -1);
    CHECK(serialized == NULL);
    CHECK_EQ_INT((long)serialized_length, 0);
    free(serialized);
}

TEST(upsert_replaces_only_the_exact_publication_destination) {
    publication_record_t original;
    publication_record_t replacement;
    publication_record_t other_repository;
    publication_ledger_t ledger;
    const publication_record_t *found;

    fill_gpg_record(&original, "/tmp/ar11-publication/repository",
                    FINGERPRINT_A);
    replacement = original;
    snprintf(replacement.gpg_fingerprint,
             sizeof(replacement.gpg_fingerprint), "%s", FINGERPRINT_B);
    replacement.state = PUBLICATION_STATE_RETIRING;
    /* Namespace ownership is stable across metadata generations: updating
     * the same parent object must replace, not create an ambiguous duplicate. */
    replacement.config_parent.mode = (uintmax_t)(S_IFDIR | 0750);
    replacement.config_parent.ctime_nanoseconds--;
    other_repository = original;
    snprintf(other_repository.repository_path,
             sizeof(other_repository.repository_path), "%s",
             "/tmp/ar11-publication/other-repository");
    other_repository.repository.inode = UINTMAX_C(202);

    publication_ledger_init(&ledger);
    CHECK_EQ_INT(publication_ledger_upsert(&ledger, &original), 0);
    CHECK_EQ_INT(publication_ledger_upsert(&ledger, &replacement), 0);
    CHECK_EQ_INT((int)ledger.count, 1);
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ledger, UINT32_C(41), INCARNATION_A,
                     PUBLICATION_SCOPE_LOCAL,
                     "/tmp/ar11-publication/repository/.git/config",
                     "/tmp/ar11-publication/repository", &found),
                 PUBLICATION_LOOKUP_FOUND);
    CHECK(found != NULL);
    if (found) {
        CHECK_STR_EQ(found->gpg_fingerprint, FINGERPRINT_B);
        CHECK_EQ_INT((int)found->state,
                     (int)PUBLICATION_STATE_RETIRING);
    }

    CHECK_EQ_INT(publication_ledger_upsert(&ledger, &other_repository), 0);
    CHECK_EQ_INT((int)ledger.count, 2);
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ledger, UINT32_C(41), INCARNATION_A,
                     PUBLICATION_SCOPE_LOCAL,
                     "/tmp/ar11-publication/repository/.git/config",
                     "/tmp/ar11-publication/other-repository", &found),
                 PUBLICATION_LOOKUP_FOUND);
    check_record_identity(found, "/tmp/ar11-publication/other-repository",
                          FINGERPRINT_A);
    publication_ledger_clear(&ledger);
}

TEST(destination_aliases_share_one_canonical_upsert_lookup_and_live_key) {
    char root[MAX_PATH_LEN] = "/tmp/gsw-ar14-publication-alias.XXXXXX";
    char repository[MAX_PATH_LEN];
    char config_parent[MAX_PATH_LEN];
    char config_path[MAX_PATH_LEN];
    char repository_alias[MAX_PATH_LEN];
    char alias_config[MAX_PATH_LEN];
    char alias_repository[MAX_PATH_LEN];
    publication_record_t canonical;
    publication_record_t alias;
    publication_record_t replacement;
    publication_ledger_t ledger;
    const publication_record_t *found = NULL;
    const publication_record_t *generation_records[1];
    int fd = -1;
    static const char contents[] = "[alias]\n";

    publication_ledger_init(&ledger);
    CHECK(ts_mkdtemp(root) != NULL);
    if (!root[0] || ts_canonicalize_dir_path(root, sizeof(root)) != 0 ||
        snprintf(repository, sizeof(repository), "%s/repository", root) >=
            (int)sizeof(repository) ||
        snprintf(config_parent, sizeof(config_parent), "%s/.git",
                 repository) >= (int)sizeof(config_parent) ||
        snprintf(config_path, sizeof(config_path), "%s/config",
                 config_parent) >= (int)sizeof(config_path) ||
        snprintf(repository_alias, sizeof(repository_alias), "%s/repo-link",
                 root) >= (int)sizeof(repository_alias) ||
        mkdir(repository, 0700) != 0 ||
        mkdir(config_parent, 0700) != 0) {
        CHECK(false);
        goto cleanup;
    }
    fd = open(config_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0 ||
        write(fd, contents, sizeof(contents) - 1U) !=
            (ssize_t)(sizeof(contents) - 1U) ||
        close(fd) != 0 ||
        symlink(repository, repository_alias) != 0) {
        CHECK(false);
        fd = -1;
        goto cleanup;
    }
    fd = -1;
    if (snprintf(alias_config, sizeof(alias_config),
                 "%s//.git/./config", repository_alias) >=
            (int)sizeof(alias_config) ||
        snprintf(alias_repository, sizeof(alias_repository), "%s//.",
                 repository_alias) >= (int)sizeof(alias_repository)) {
        CHECK(false);
        goto cleanup;
    }

    fill_gpg_record(&canonical, repository, FINGERPRINT_A);
    CHECK_EQ_INT(bind_live_local_destination(
                     &canonical, repository, config_parent, config_path), 0);
    alias = canonical;
    CHECK_EQ_INT(safe_strncpy(alias.config_path, alias_config,
                              sizeof(alias.config_path)), 0);
    CHECK_EQ_INT(safe_strncpy(alias.repository_path, alias_repository,
                              sizeof(alias.repository_path)), 0);

    errno = E2BIG;
    CHECK(publication_record_same_config_destination(&canonical, &alias));
    CHECK(publication_record_same_destination(&canonical, &alias));
    CHECK_EQ_INT(errno, E2BIG);

    CHECK_EQ_INT(publication_ledger_upsert(&ledger, &alias), 0);
    CHECK_EQ_INT((long)ledger.count, 1);
    CHECK_STR_EQ(ledger.records[0].config_path, config_path);
    CHECK_STR_EQ(ledger.records[0].repository_path, repository);

    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ledger, canonical.account_id,
                     canonical.account_incarnation, canonical.scope,
                     alias_config, alias_repository, &found),
                 PUBLICATION_LOOKUP_FOUND);
    CHECK(found == &ledger.records[0]);
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ledger, canonical.account_id,
                     canonical.account_incarnation, canonical.scope,
                     config_path, repository, &found),
                 PUBLICATION_LOOKUP_FOUND);
    CHECK(found == &ledger.records[0]);

    replacement = alias;
    snprintf(replacement.gpg_fingerprint,
             sizeof(replacement.gpg_fingerprint), "%s", FINGERPRINT_B);
    CHECK_EQ_INT(publication_ledger_upsert(&ledger, &replacement), 0);
    CHECK_EQ_INT((long)ledger.count, 1);
    CHECK_STR_EQ(ledger.records[0].config_path, config_path);
    CHECK_STR_EQ(ledger.records[0].repository_path, repository);
    CHECK_STR_EQ(ledger.records[0].gpg_fingerprint, FINGERPRINT_B);

    generation_records[0] = &ledger.records[0];
    CHECK_EQ_INT(publication_record_verify_live_destination(
                     &ledger.records[0], generation_records, 1U, &found), 0);
    CHECK(found == &ledger.records[0]);

cleanup:
    if (fd >= 0) close(fd);
    publication_ledger_clear(&ledger);
    ts_rm_rf(root);
}

TEST(absent_config_leaf_uses_anchored_parent_but_conflicts_stay_unresolved) {
    char root[MAX_PATH_LEN] = "/tmp/gsw-ar14-publication-absent.XXXXXX";
    char repository[MAX_PATH_LEN];
    char config_parent[MAX_PATH_LEN];
    char config_path[MAX_PATH_LEN];
    char repository_alias[MAX_PATH_LEN];
    char missing_alias[MAX_PATH_LEN];
    char expected_missing[MAX_PATH_LEN];
    char dangling_path[MAX_PATH_LEN];
    char dangling_alias[MAX_PATH_LEN];
    char conflicting_alias[MAX_PATH_LEN];
    publication_record_t live;
    publication_record_t absent;
    publication_record_t dangling;
    publication_record_t conflicting;
    publication_ledger_t ledger;
    int fd = -1;
    static const char contents[] = "[anchor]\n";

    publication_ledger_init(&ledger);
    CHECK(ts_mkdtemp(root) != NULL);
    if (!root[0] || ts_canonicalize_dir_path(root, sizeof(root)) != 0 ||
        snprintf(repository, sizeof(repository), "%s/repository", root) >=
            (int)sizeof(repository) ||
        snprintf(config_parent, sizeof(config_parent), "%s/.git",
                 repository) >= (int)sizeof(config_parent) ||
        snprintf(config_path, sizeof(config_path), "%s/config",
                 config_parent) >= (int)sizeof(config_path) ||
        snprintf(repository_alias, sizeof(repository_alias), "%s/repo-link",
                 root) >= (int)sizeof(repository_alias) ||
        mkdir(repository, 0700) != 0 ||
        mkdir(config_parent, 0700) != 0) {
        CHECK(false);
        goto cleanup;
    }
    fd = open(config_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0 ||
        write(fd, contents, sizeof(contents) - 1U) !=
            (ssize_t)(sizeof(contents) - 1U) ||
        close(fd) != 0 ||
        symlink(repository, repository_alias) != 0) {
        CHECK(false);
        fd = -1;
        goto cleanup;
    }
    fd = -1;
    if (snprintf(missing_alias, sizeof(missing_alias),
                 "%s//.git/./future-config", repository_alias) >=
            (int)sizeof(missing_alias) ||
        snprintf(expected_missing, sizeof(expected_missing),
                 "%s/future-config", config_parent) >=
            (int)sizeof(expected_missing) ||
        snprintf(dangling_path, sizeof(dangling_path), "%s/dangling",
                 config_parent) >= (int)sizeof(dangling_path) ||
        snprintf(dangling_alias, sizeof(dangling_alias), "%s/.git/dangling",
                 repository_alias) >= (int)sizeof(dangling_alias) ||
        snprintf(conflicting_alias, sizeof(conflicting_alias),
                 "%s/.git/config", repository_alias) >=
            (int)sizeof(conflicting_alias) ||
        symlink("/definitely/missing/ar14-target", dangling_path) != 0) {
        CHECK(false);
        goto cleanup;
    }

    fill_gpg_record(&live, repository, FINGERPRINT_A);
    CHECK_EQ_INT(bind_live_local_destination(
                     &live, repository, config_parent, config_path), 0);

    absent = live;
    CHECK_EQ_INT(safe_strncpy(absent.config_path, missing_alias,
                              sizeof(absent.config_path)), 0);
    CHECK_EQ_INT(publication_ledger_upsert(&ledger, &absent), 0);
    CHECK_STR_EQ(ledger.records[0].config_path, expected_missing);
    CHECK_STR_EQ(ledger.records[0].repository_path, repository);

    publication_ledger_clear(&ledger);
    dangling = live;
    CHECK_EQ_INT(safe_strncpy(dangling.config_path, dangling_alias,
                              sizeof(dangling.config_path)), 0);
    CHECK_EQ_INT(publication_ledger_upsert(&ledger, &dangling), 0);
    CHECK_STR_EQ(ledger.records[0].config_path, dangling_alias);
    CHECK_STR_EQ(ledger.records[0].repository_path, repository);

    publication_ledger_clear(&ledger);
    conflicting = live;
    conflicting.config_parent.inode++;
    CHECK_EQ_INT(safe_strncpy(conflicting.config_path, conflicting_alias,
                              sizeof(conflicting.config_path)), 0);
    CHECK_EQ_INT(publication_ledger_upsert(&ledger, &conflicting), 0);
    CHECK_STR_EQ(ledger.records[0].config_path, conflicting_alias);
    CHECK_STR_EQ(ledger.records[0].repository_path, repository);
    CHECK(!publication_record_same_config_destination(&live, &conflicting));

cleanup:
    if (fd >= 0) close(fd);
    publication_ledger_clear(&ledger);
    ts_rm_rf(root);
}

TEST(offline_destination_spellings_round_trip_without_ancestry_rewrite) {
    publication_record_t record;
    publication_ledger_t source;
    publication_ledger_t loaded;
    publication_ledger_t ancestry;
    const publication_record_t *found = NULL;
    unsigned char *serialized = NULL;
    unsigned char *reserialized = NULL;
    size_t serialized_length = 0U;
    size_t reserialized_length = 0U;
    static const char config_alias[] =
        "/offline-ar14//repository/./.git/config";
    static const char repository_alias[] =
        "/offline-ar14//repository/.";
    static const char ancestry_config[] =
        "/offline-ar14/base/../repository/.git/config";
    static const char ancestry_repository[] =
        "/offline-ar14/base/../repository";

    publication_ledger_init(&source);
    publication_ledger_init(&loaded);
    publication_ledger_init(&ancestry);
    fill_gpg_record(&record, repository_alias, FINGERPRINT_A);
    CHECK_EQ_INT(safe_strncpy(record.config_path, config_alias,
                              sizeof(record.config_path)), 0);
    source.present = true;
    source.version = PUBLICATION_LEDGER_VERSION;
    source.records = &record;
    source.count = 1U;

    CHECK_EQ_INT(publication_ledger_serialize(
                     &source, &serialized, &serialized_length), 0);
    CHECK_EQ_INT(publication_ledger_parse(
                     serialized, serialized_length, &loaded), 0);
    CHECK_STR_EQ(loaded.records[0].config_path, config_alias);
    CHECK_STR_EQ(loaded.records[0].repository_path, repository_alias);
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &loaded, record.account_id, record.account_incarnation,
                     record.scope,
                     "/offline-ar14/repository/.git/config",
                     "/offline-ar14/repository", &found),
                 PUBLICATION_LOOKUP_FOUND);
    CHECK(found == &loaded.records[0]);
    CHECK_EQ_INT(publication_ledger_serialize(
                     &loaded, &reserialized, &reserialized_length), 0);
    CHECK_EQ_INT((long)reserialized_length, (long)serialized_length);
    if (serialized && reserialized &&
        serialized_length == reserialized_length) {
        CHECK(memcmp(serialized, reserialized, serialized_length) == 0);
    }

    CHECK_EQ_INT(safe_strncpy(record.config_path, ancestry_config,
                              sizeof(record.config_path)), 0);
    CHECK_EQ_INT(safe_strncpy(record.repository_path, ancestry_repository,
                              sizeof(record.repository_path)), 0);
    CHECK_EQ_INT(publication_ledger_upsert(&ancestry, &record), 0);
    CHECK_STR_EQ(ancestry.records[0].config_path, ancestry_config);
    CHECK_STR_EQ(ancestry.records[0].repository_path, ancestry_repository);
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ancestry, record.account_id,
                     record.account_incarnation, record.scope,
                     "/offline-ar14/repository/.git/config",
                     "/offline-ar14/repository", &found),
                 PUBLICATION_LOOKUP_ABSENT);

    free(reserialized);
    free(serialized);
    publication_ledger_clear(&ancestry);
    publication_ledger_clear(&loaded);
}

TEST(alias_duplicate_destinations_fail_closed_in_serializer_and_parser) {
    char root[MAX_PATH_LEN] = "/tmp/gsw-ar14-publication-duplicate.XXXXXX";
    char repository[MAX_PATH_LEN];
    char config_parent[MAX_PATH_LEN];
    char config_path[MAX_PATH_LEN];
    char repository_alias[MAX_PATH_LEN];
    char alias_config[MAX_PATH_LEN];
    char distinct_config[MAX_PATH_LEN];
    char distinct_repository[MAX_PATH_LEN];
    char config_hex[MAX_PATH_LEN * 2U + 1U];
    char repository_hex[MAX_PATH_LEN * 2U + 1U];
    publication_record_t records[2];
    publication_ledger_t ledger;
    publication_ledger_t parsed;
    unsigned char *serialized = NULL;
    unsigned char *config_replaced = NULL;
    unsigned char *alias_bytes = NULL;
    size_t serialized_length = 0U;
    size_t config_replaced_length = 0U;
    size_t alias_length = 0U;
    int fd = -1;
    static const char contents[] = "[duplicate]\n";

    publication_ledger_init(&ledger);
    publication_ledger_init(&parsed);
    CHECK(ts_mkdtemp(root) != NULL);
    if (!root[0] || ts_canonicalize_dir_path(root, sizeof(root)) != 0 ||
        snprintf(repository, sizeof(repository), "%s/repository", root) >=
            (int)sizeof(repository) ||
        snprintf(config_parent, sizeof(config_parent), "%s/.git",
                 repository) >= (int)sizeof(config_parent) ||
        snprintf(config_path, sizeof(config_path), "%s/config",
                 config_parent) >= (int)sizeof(config_path) ||
        snprintf(repository_alias, sizeof(repository_alias), "%s/repo-link",
                 root) >= (int)sizeof(repository_alias) ||
        mkdir(repository, 0700) != 0 ||
        mkdir(config_parent, 0700) != 0) {
        CHECK(false);
        goto cleanup;
    }
    fd = open(config_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0 ||
        write(fd, contents, sizeof(contents) - 1U) !=
            (ssize_t)(sizeof(contents) - 1U) ||
        close(fd) != 0 ||
        symlink(repository, repository_alias) != 0) {
        CHECK(false);
        fd = -1;
        goto cleanup;
    }
    fd = -1;
    if (snprintf(alias_config, sizeof(alias_config),
                 "%s//.git/./config", repository_alias) >=
            (int)sizeof(alias_config) ||
        snprintf(distinct_config, sizeof(distinct_config),
                 "%s/offline/.git/config", root) >=
            (int)sizeof(distinct_config) ||
        snprintf(distinct_repository, sizeof(distinct_repository),
                 "%s/offline", root) >= (int)sizeof(distinct_repository) ||
        encode_upper_hex(alias_config, config_hex, sizeof(config_hex)) != 0 ||
        encode_upper_hex(repository_alias, repository_hex,
                         sizeof(repository_hex)) != 0) {
        CHECK(false);
        goto cleanup;
    }

    fill_gpg_record(&records[0], repository, FINGERPRINT_A);
    CHECK_EQ_INT(bind_live_local_destination(
                     &records[0], repository, config_parent, config_path), 0);
    records[1] = records[0];
    records[1].account_id++;
    CHECK_EQ_INT(safe_strncpy(records[1].config_path, alias_config,
                              sizeof(records[1].config_path)), 0);
    CHECK_EQ_INT(safe_strncpy(records[1].repository_path, repository_alias,
                              sizeof(records[1].repository_path)), 0);
    ledger.present = true;
    ledger.version = PUBLICATION_LEDGER_VERSION;
    ledger.records = records;
    ledger.count = 2U;
    clear_error();
    CHECK_EQ_INT(publication_ledger_serialize(
                     &ledger, &serialized, &serialized_length), -1);
    CHECK(serialized == NULL);
    CHECK(strstr(get_last_error()->message, "duplicate destinations") != NULL);

    CHECK_EQ_INT(safe_strncpy(records[1].config_path, distinct_config,
                              sizeof(records[1].config_path)), 0);
    CHECK_EQ_INT(safe_strncpy(records[1].repository_path,
                              distinct_repository,
                              sizeof(records[1].repository_path)), 0);
    CHECK_EQ_INT(publication_ledger_serialize(
                     &ledger, &serialized, &serialized_length), 0);
    config_replaced = replace_serialized_field_value(
        serialized, serialized_length, "p.1.config=", config_hex,
        &config_replaced_length);
    CHECK(config_replaced != NULL);
    if (config_replaced) {
        alias_bytes = replace_serialized_field_value(
            config_replaced, config_replaced_length, "p.1.repository=",
            repository_hex, &alias_length);
    }
    CHECK(alias_bytes != NULL);
    clear_error();
    if (alias_bytes) {
        CHECK_EQ_INT(publication_ledger_parse(
                         alias_bytes, alias_length, &parsed), -1);
    }
    CHECK(!parsed.present);
    CHECK(strstr(get_last_error()->message, "duplicate destinations") != NULL);

cleanup:
    if (fd >= 0) close(fd);
    free(alias_bytes);
    free(config_replaced);
    free(serialized);
    publication_ledger_clear(&parsed);
    ts_rm_rf(root);
}

TEST(upsert_rejects_offline_aliases_that_converge_without_model_mutation) {
    char root[MAX_PATH_LEN] = "/tmp/gsw-ar14-publication-converge.XXXXXX";
    char repository[MAX_PATH_LEN];
    char config_parent[MAX_PATH_LEN];
    char config_path[MAX_PATH_LEN];
    char alias_a[MAX_PATH_LEN];
    char alias_b[MAX_PATH_LEN];
    char config_a[MAX_PATH_LEN];
    char config_b[MAX_PATH_LEN];
    publication_record_t incoming;
    publication_record_t records[2];
    publication_record_t before[2];
    publication_record_t *records_before;
    publication_ledger_t source;
    publication_ledger_t parsed;
    unsigned char *serialized = NULL;
    size_t serialized_length = 0U;
    size_t count_before;
    unsigned int version_before;
    bool present_before;
    int fd = -1;
    static const char contents[] = "[converge]\n";

    publication_ledger_init(&source);
    publication_ledger_init(&parsed);
    CHECK(ts_mkdtemp(root) != NULL);
    if (!root[0] || ts_canonicalize_dir_path(root, sizeof(root)) != 0 ||
        snprintf(repository, sizeof(repository), "%s/repository", root) >=
            (int)sizeof(repository) ||
        snprintf(config_parent, sizeof(config_parent), "%s/.git",
                 repository) >= (int)sizeof(config_parent) ||
        snprintf(config_path, sizeof(config_path), "%s/config",
                 config_parent) >= (int)sizeof(config_path) ||
        snprintf(alias_a, sizeof(alias_a), "%s/offline-a", root) >=
            (int)sizeof(alias_a) ||
        snprintf(alias_b, sizeof(alias_b), "%s/offline-b", root) >=
            (int)sizeof(alias_b) ||
        snprintf(config_a, sizeof(config_a), "%s/.git/config", alias_a) >=
            (int)sizeof(config_a) ||
        snprintf(config_b, sizeof(config_b), "%s/.git/config", alias_b) >=
            (int)sizeof(config_b) ||
        mkdir(repository, 0700) != 0 ||
        mkdir(config_parent, 0700) != 0) {
        CHECK(false);
        goto cleanup;
    }
    fd = open(config_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0 ||
        write(fd, contents, sizeof(contents) - 1U) !=
            (ssize_t)(sizeof(contents) - 1U) ||
        close(fd) != 0) {
        CHECK(false);
        fd = -1;
        goto cleanup;
    }
    fd = -1;

    fill_gpg_record(&incoming, repository, FINGERPRINT_A);
    CHECK_EQ_INT(bind_live_local_destination(
                     &incoming, repository, config_parent, config_path), 0);
    records[0] = incoming;
    records[1] = incoming;
    records[1].account_id++;
    CHECK_EQ_INT(safe_strncpy(records[0].config_path, config_a,
                              sizeof(records[0].config_path)), 0);
    CHECK_EQ_INT(safe_strncpy(records[0].repository_path, alias_a,
                              sizeof(records[0].repository_path)), 0);
    CHECK_EQ_INT(safe_strncpy(records[1].config_path, config_b,
                              sizeof(records[1].config_path)), 0);
    CHECK_EQ_INT(safe_strncpy(records[1].repository_path, alias_b,
                              sizeof(records[1].repository_path)), 0);

    /* Step 1/2: while both aliases are offline, their byte-distinct spellings
     * are a valid legacy ledger and survive serialization plus parsing. */
    source.present = true;
    source.version = PUBLICATION_LEDGER_VERSION;
    source.records = records;
    source.count = 2U;
    CHECK_EQ_INT(publication_ledger_serialize(
                     &source, &serialized, &serialized_length), 0);
    CHECK_EQ_INT(publication_ledger_parse(
                     serialized, serialized_length, &parsed), 0);
    CHECK_EQ_INT((long)parsed.count, 2);

    records_before = parsed.records;
    count_before = parsed.count;
    version_before = parsed.version;
    present_before = parsed.present;
    memcpy(before, parsed.records, sizeof(before));

    /* Step 3: both previously unresolved names now resolve to the exact same
     * anchored repository and config parent. */
    CHECK_EQ_INT(symlink(repository, alias_a), 0);
    CHECK_EQ_INT(symlink(repository, alias_b), 0);

    /* Step 4: upsert must classify every existing match before mutation.
     * Replacing only the first would leave a second live alias and an
     * ambiguous ownership model. */
    clear_error();
    CHECK_EQ_INT(publication_ledger_upsert(&parsed, &incoming), -1);
    CHECK(strstr(get_last_error()->message, "ambiguous") != NULL);
    CHECK(parsed.records == records_before);
    CHECK_EQ_INT((long)parsed.count, (long)count_before);
    CHECK_EQ_INT((int)parsed.version, (int)version_before);
    CHECK(parsed.present == present_before);
    CHECK(memcmp(parsed.records, before, sizeof(before)) == 0);

cleanup:
    if (fd >= 0) close(fd);
    free(serialized);
    publication_ledger_clear(&parsed);
    ts_rm_rf(root);
}

TEST(guarded_publication_clears_install_state_before_input_validation) {
    gitswitch_ctx_t ctx;
    publication_record_t invalid_record;
    publication_record_t valid_record;
    config_resume_hint_snapshot_t snapshot = {0};
    bool installed = true;

    memset(&ctx, 0, sizeof(ctx));
    publication_record_init(&invalid_record);
    snapshot.valid = true;
    snprintf(snapshot.config_path, sizeof(snapshot.config_path), "%s",
             "/tmp/ar11-invalid-publication/accounts.toml");

    clear_error();
    CHECK_EQ_INT(
        config_save_active_account_publication_transactional_guarded(
            &ctx, snapshot.config_path, &invalid_record, &installed,
            &snapshot),
        -1);
    CHECK(!installed);

    fill_gpg_record(&valid_record, "/tmp/ar11-publication/repository",
                    FINGERPRINT_A);
    config_resume_hint_snapshot_clear(&snapshot);
    installed = true;
    clear_error();
    CHECK_EQ_INT(
        config_save_active_account_publication_transactional_guarded(
            &ctx, "/tmp/ar11-invalid-snapshot/accounts.toml", &valid_record,
            &installed, &snapshot),
        -1);
    CHECK(!installed);
    config_resume_hint_snapshot_clear(&snapshot);
}

TEST(guarded_publication_requires_the_exact_live_active_incarnation) {
    gitswitch_ctx_t ctx;
    account_t detached;
    publication_record_t record;
    config_resume_hint_snapshot_t snapshot;
    bool installed;

    fill_active_context(&ctx);
    detached = ctx.accounts[0];
    fill_global_gpg_record(&record, ctx.accounts[0].id,
                           "/tmp/ar11-owner-binding.gitconfig",
                           FINGERPRINT_A);
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.valid = true;

    ctx.current_account = &detached;
    installed = true;
    errno = 0;
    clear_error();
    CHECK_EQ_INT(
        config_save_active_account_publication_transactional_guarded(
            &ctx, "/tmp/ar11-owner-binding.toml", &record, &installed,
            &snapshot),
        -1);
    CHECK(!installed);
    CHECK_EQ_INT(errno, ESTALE);

    ctx.current_account = NULL;
    installed = true;
    errno = 0;
    clear_error();
    CHECK_EQ_INT(
        config_save_active_account_publication_transactional_guarded(
            &ctx, "/tmp/ar11-owner-binding.toml", &record, &installed,
            &snapshot),
        -1);
    CHECK(!installed);
    CHECK_EQ_INT(errno, ESTALE);

    ctx.current_account = &ctx.accounts[0];
    record.account_id++;
    installed = true;
    errno = 0;
    clear_error();
    CHECK_EQ_INT(
        config_save_active_account_publication_transactional_guarded(
            &ctx, "/tmp/ar11-owner-binding.toml", &record, &installed,
            &snapshot),
        -1);
    CHECK(!installed);
    CHECK_EQ_INT(errno, ESTALE);
    record.account_id = ctx.accounts[0].id;

    snprintf(record.account_incarnation,
             sizeof(record.account_incarnation), "%s", INCARNATION_B);
    installed = true;
    errno = 0;
    clear_error();
    CHECK_EQ_INT(
        config_save_active_account_publication_transactional_guarded(
            &ctx, "/tmp/ar11-owner-binding.toml", &record, &installed,
            &snapshot),
        -1);
    CHECK(!installed);
    CHECK_EQ_INT(errno, ESTALE);
    snprintf(record.account_incarnation,
             sizeof(record.account_incarnation), "%s", INCARNATION_A);

    ctx.accounts[0].incarnation_persisted = false;
    installed = true;
    errno = 0;
    clear_error();
    CHECK_EQ_INT(
        config_save_active_account_publication_transactional_guarded(
            &ctx, "/tmp/ar11-owner-binding.toml", &record, &installed,
            &snapshot),
        -1);
    CHECK(!installed);
    CHECK_EQ_INT(errno, ESTALE);
    ctx.accounts[0].incarnation_persisted = true;

    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "different-account");
    installed = true;
    errno = 0;
    clear_error();
    CHECK_EQ_INT(
        config_save_active_account_publication_transactional_guarded(
            &ctx, "/tmp/ar11-owner-binding.toml", &record, &installed,
            &snapshot),
        -1);
    CHECK(!installed);
    CHECK_EQ_INT(errno, ESTALE);
}

TEST(guarded_publication_preserves_intervening_writer_generation) {
    char home[MAX_PATH_LEN];
    char config_path[MAX_PATH_LEN];
    char state_path[MAX_PATH_LEN];
    char git_config_path[MAX_PATH_LEN];
    char *saved_home = NULL;
    const char *home_before = getenv("HOME");
    gitswitch_ctx_t ctx;
    publication_record_t record;
    publication_ledger_t ledger;
    config_resume_hint_snapshot_t snapshot = {0};
    unsigned char *writer_bytes = NULL;
    unsigned char *after_bytes = NULL;
    size_t writer_length = 0U;
    size_t after_length = 0U;
    bool installed = true;

    if (home_before) {
        saved_home = strdup(home_before);
        CHECK(saved_home != NULL);
    }
    CHECK_EQ_INT(make_private_config_home(
                     home, sizeof(home), config_path, sizeof(config_path),
                     state_path, sizeof(state_path)), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    fill_active_context(&ctx);
    ctx.config.active_account[0] = '\0';
    CHECK_EQ_INT(config_save(&ctx, config_path), 0);
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&snapshot), 0);

    /* Both writes use the public lock-taking API. Ending on the original
     * bytes proves that the publication guard compares the exact captured
     * generation, not merely its content. */
    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "alice");
    CHECK_EQ_INT(config_save_active_account(&ctx, config_path), 0);
    ctx.config.active_account[0] = '\0';
    CHECK_EQ_INT(config_save_active_account(&ctx, config_path), 0);
    CHECK_EQ_INT(read_file_alloc(state_path, &writer_bytes, &writer_length),
                 0);

    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account),
             "%s", "alice");
    CHECK_EQ_INT(join_path(git_config_path, sizeof(git_config_path), home,
                           "global.gitconfig"), 0);
    fill_global_gpg_record(&record, UINT32_C(41), git_config_path,
                           FINGERPRINT_A);
    clear_error();
    CHECK_EQ_INT(
        config_save_active_account_publication_transactional_guarded(
            &ctx, config_path, &record, &installed, &snapshot),
        -1);
    CHECK(!installed);
    CHECK(strstr(get_last_error()->message,
                 "before-image changed") != NULL);

    CHECK_EQ_INT(read_file_alloc(state_path, &after_bytes, &after_length), 0);
    CHECK_EQ_INT((long)after_length, (long)writer_length);
    if (writer_bytes && after_bytes && writer_length == after_length) {
        CHECK(memcmp(writer_bytes, after_bytes, writer_length) == 0);
    }
    publication_ledger_init(&ledger);
    CHECK_EQ_INT(config_load_publication_ledger(config_path, &ledger), 0);
    CHECK(!ledger.present);
    CHECK_EQ_INT((int)ledger.count, 0);
    publication_ledger_clear(&ledger);

    config_resume_hint_snapshot_clear(&snapshot);
    free(after_bytes);
    free(writer_bytes);
    if (saved_home) {
        CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("HOME"), 0);
    }
    free(saved_home);
    ts_rm_rf(home);
}

TEST(active_state_bundle_round_trip_and_failed_save_restore_old_ledger) {
    char home[MAX_PATH_LEN];
    char config_path[MAX_PATH_LEN];
    char state_path[MAX_PATH_LEN];
    char git_config_path[MAX_PATH_LEN];
    char *saved_home = NULL;
    const char *home_before = getenv("HOME");
    gitswitch_ctx_t ctx;
    publication_record_t old_record;
    publication_record_t replacement;
    publication_ledger_t ledger;
    config_resume_hint_snapshot_t snapshot = {0};
    unsigned char *legacy_bytes = NULL;
    unsigned char *old_bytes = NULL;
    unsigned char *restored_bytes = NULL;
    size_t legacy_length = 0;
    size_t old_length = 0;
    size_t restored_length = 0;
    const publication_record_t *found;
    bool installed = false;

    if (home_before) {
        saved_home = strdup(home_before);
        CHECK(saved_home != NULL);
    }
    CHECK_EQ_INT(make_private_config_home(
                     home, sizeof(home), config_path, sizeof(config_path),
                     state_path, sizeof(state_path)), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    fill_active_context(&ctx);
    CHECK_EQ_INT(config_save(&ctx, config_path), 0);
    CHECK_EQ_INT(read_file_alloc(state_path, &legacy_bytes,
                                 &legacy_length), 0);

    publication_ledger_init(&ledger);
    CHECK_EQ_INT(config_load_publication_ledger(config_path, &ledger), 0);
    CHECK(!ledger.present);
    CHECK_EQ_INT((int)ledger.count, 0);
    publication_ledger_clear(&ledger);

    CHECK_EQ_INT(join_path(git_config_path, sizeof(git_config_path), home,
                           "global.gitconfig"), 0);
    fill_global_gpg_record(&old_record, UINT32_C(41), git_config_path,
                           FINGERPRINT_A);
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&snapshot), 0);
    installed = false;
    CHECK_EQ_INT(
        config_save_active_account_publication_transactional_guarded(
            &ctx, config_path, &old_record, &installed, &snapshot),
        0);
    CHECK(installed);
    config_resume_hint_snapshot_clear(&snapshot);
    CHECK_EQ_INT(read_file_alloc(state_path, &old_bytes, &old_length), 0);
    CHECK(old_length > legacy_length);
    if (old_bytes && legacy_bytes && old_length >= legacy_length) {
        CHECK(memcmp(old_bytes, legacy_bytes, legacy_length) == 0);
    }

    publication_ledger_init(&ledger);
    CHECK_EQ_INT(config_load_publication_ledger(config_path, &ledger), 0);
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ledger, UINT32_C(41), INCARNATION_A,
                     PUBLICATION_SCOPE_GLOBAL, git_config_path, "", &found),
                 PUBLICATION_LOOKUP_FOUND);
    CHECK(found != NULL);
    if (found) CHECK_STR_EQ(found->gpg_fingerprint, FINGERPRINT_A);
    publication_ledger_clear(&ledger);

    replacement = old_record;
    snprintf(replacement.gpg_fingerprint,
             sizeof(replacement.gpg_fingerprint), "%s", FINGERPRINT_B);
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&snapshot), 0);
    publication_fault_target = CONFIG_IO_STATE_BEFORE_DIR_SYNC;
    config_set_io_fault_fn(fail_publication_boundary);
    installed = false;
    clear_error();
    CHECK_EQ_INT(
        config_save_active_account_publication_transactional_guarded(
            &ctx, config_path, &replacement, &installed, &snapshot),
        -1);
    config_set_io_fault_fn(NULL);
    CHECK(installed);
    CHECK_EQ_INT(config_resume_hint_snapshot_restore(&snapshot), 0);
    config_resume_hint_snapshot_clear(&snapshot);

    CHECK_EQ_INT(read_file_alloc(state_path, &restored_bytes,
                                 &restored_length), 0);
    CHECK_EQ_INT((long)restored_length, (long)old_length);
    if (restored_bytes && old_bytes && restored_length == old_length) {
        CHECK(memcmp(restored_bytes, old_bytes, old_length) == 0);
    }
    publication_ledger_init(&ledger);
    CHECK_EQ_INT(config_load_publication_ledger(config_path, &ledger), 0);
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ledger, UINT32_C(41), INCARNATION_A,
                     PUBLICATION_SCOPE_GLOBAL, git_config_path, "", &found),
                 PUBLICATION_LOOKUP_FOUND);
    CHECK(found != NULL);
    if (found) CHECK_STR_EQ(found->gpg_fingerprint, FINGERPRINT_A);
    publication_ledger_clear(&ledger);

    config_set_io_fault_fn(NULL);
    config_resume_hint_snapshot_clear(&snapshot);
    free(restored_bytes);
    free(old_bytes);
    free(legacy_bytes);
    if (saved_home) {
        CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("HOME"), 0);
    }
    free(saved_home);
}

TEST(legacy_read_is_observational_and_migration_binds_all_accounts_once) {
    char home[MAX_PATH_LEN];
    char config_path[MAX_PATH_LEN];
    char state_path[MAX_PATH_LEN];
    char *saved_home = NULL;
    const char *home_before = getenv("HOME");
    gitswitch_ctx_t ctx;
    gitswitch_ctx_t reloaded;
    config_incarnation_generate_fn previous_generator;
    unsigned char *before = NULL;
    unsigned char *after_read = NULL;
    unsigned char *after_migration = NULL;
    size_t before_length = 0U;
    size_t after_read_length = 0U;
    size_t after_migration_length = 0U;
    bool installed = false;

    if (home_before) {
        saved_home = strdup(home_before);
        CHECK(saved_home != NULL);
    }
    CHECK_EQ_INT(make_private_config_home(
                     home, sizeof(home), config_path, sizeof(config_path),
                     state_path, sizeof(state_path)), 0);
    CHECK_EQ_INT(write_private_bytes(
                     config_path, legacy_two_account_document,
                     sizeof(legacy_two_account_document) - 1U), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    CHECK_EQ_INT(read_file_alloc(config_path, &before, &before_length), 0);

    incarnation_generator_calls = 0U;
    incarnation_generator_success_limit = 2U;
    previous_generator = config_set_incarnation_generate_fn(
        deterministic_incarnation_generator);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_init_names(&ctx), 0);
    CHECK_EQ_INT((long)ctx.account_count, 2);
    CHECK_EQ_INT((long)incarnation_generator_calls, 0);
    for (size_t i = 0; i < ctx.account_count; i++) {
        CHECK_STR_EQ(ctx.accounts[i].incarnation, "");
        CHECK(!ctx.accounts[i].incarnation_persisted);
    }
    CHECK_EQ_INT(access(state_path, F_OK), -1);
    CHECK_EQ_INT(errno, ENOENT);
    CHECK_EQ_INT(read_file_alloc(config_path, &after_read,
                                 &after_read_length), 0);
    CHECK_EQ_INT((long)after_read_length, (long)before_length);
    if (before && after_read && before_length == after_read_length) {
        CHECK(memcmp(before, after_read, before_length) == 0);
    }

    CHECK_EQ_INT(config_migrate_account_incarnations(
                     &ctx, config_path, &installed), 0);
    CHECK(installed);
    CHECK_EQ_INT((long)incarnation_generator_calls, 2);
    CHECK_STR_EQ(ctx.accounts[0].incarnation, INCARNATION_A);
    CHECK_STR_EQ(ctx.accounts[1].incarnation, INCARNATION_B);
    CHECK(ctx.accounts[0].incarnation_persisted);
    CHECK(ctx.accounts[1].incarnation_persisted);
    CHECK_EQ_INT(read_file_alloc(config_path, &after_migration,
                                 &after_migration_length), 0);
    if (after_migration) {
        CHECK(strstr((const char *)after_migration,
                     "incarnation = \"1111111111111111111111111111111111111111111111111111111111111111\"") != NULL);
        CHECK(strstr((const char *)after_migration,
                     "incarnation = \"2222222222222222222222222222222222222222222222222222222222222222\"") != NULL);
    }

    memset(&reloaded, 0, sizeof(reloaded));
    CHECK_EQ_INT(config_init_names(&reloaded), 0);
    CHECK_EQ_INT((long)incarnation_generator_calls, 2);
    CHECK_EQ_INT((long)reloaded.account_count, 2);
    CHECK_STR_EQ(reloaded.accounts[0].incarnation, INCARNATION_A);
    CHECK_STR_EQ(reloaded.accounts[1].incarnation, INCARNATION_B);
    CHECK(reloaded.accounts[0].incarnation_persisted);
    CHECK(reloaded.accounts[1].incarnation_persisted);

    config_set_incarnation_generate_fn(previous_generator);
    free(after_migration);
    free(after_read);
    free(before);
    if (saved_home) {
        CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("HOME"), 0);
    }
    free(saved_home);
    ts_rm_rf(home);
}

TEST(migration_failure_restores_file_state_and_exact_in_memory_before_image) {
    char home[MAX_PATH_LEN];
    char config_path[MAX_PATH_LEN];
    char state_path[MAX_PATH_LEN];
    char *saved_home = NULL;
    const char *home_before = getenv("HOME");
    gitswitch_ctx_t ctx;
    config_incarnation_generate_fn previous_generator;
    unsigned char *before = NULL;
    unsigned char *after = NULL;
    size_t before_length = 0U;
    size_t after_length = 0U;
    bool installed = true;

    if (home_before) {
        saved_home = strdup(home_before);
        CHECK(saved_home != NULL);
    }
    CHECK_EQ_INT(make_private_config_home(
                     home, sizeof(home), config_path, sizeof(config_path),
                     state_path, sizeof(state_path)), 0);
    CHECK_EQ_INT(write_private_bytes(
                     config_path, legacy_two_account_document,
                     sizeof(legacy_two_account_document) - 1U), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_init_names(&ctx), 0);
    CHECK_EQ_INT(read_file_alloc(config_path, &before, &before_length), 0);

    previous_generator = config_set_incarnation_generate_fn(
        deterministic_incarnation_generator);
    incarnation_generator_calls = 0U;
    incarnation_generator_success_limit = 1U;
    installed = true;
    CHECK_EQ_INT(config_migrate_account_incarnations(
                     &ctx, config_path, &installed), -1);
    CHECK(!installed);
    CHECK_EQ_INT((long)incarnation_generator_calls, 2);
    CHECK_STR_EQ(ctx.accounts[0].incarnation, "");
    CHECK_STR_EQ(ctx.accounts[1].incarnation, "");
    CHECK(!ctx.accounts[0].incarnation_persisted);
    CHECK(!ctx.accounts[1].incarnation_persisted);
    CHECK(strstr(get_last_error()->message, "entropy failure") != NULL);
    CHECK_EQ_INT(read_file_alloc(config_path, &after, &after_length), 0);
    CHECK_EQ_INT((long)after_length, (long)before_length);
    if (before && after && before_length == after_length) {
        CHECK(memcmp(before, after, before_length) == 0);
    }
    free(after);
    after = NULL;
    CHECK_EQ_INT(access(state_path, F_OK), -1);
    CHECK_EQ_INT(errno, ENOENT);

    incarnation_generator_calls = 0U;
    incarnation_generator_success_limit = 2U;
    publication_fault_target = CONFIG_IO_DOCUMENT_BEFORE_RENAME;
    config_set_io_fault_fn(fail_publication_boundary);
    installed = true;
    CHECK_EQ_INT(config_migrate_account_incarnations(
                     &ctx, config_path, &installed), -1);
    config_set_io_fault_fn(NULL);
    CHECK(!installed);
    CHECK_EQ_INT((long)incarnation_generator_calls, 2);
    CHECK_STR_EQ(ctx.accounts[0].incarnation, "");
    CHECK_STR_EQ(ctx.accounts[1].incarnation, "");
    CHECK(!ctx.accounts[0].incarnation_persisted);
    CHECK(!ctx.accounts[1].incarnation_persisted);
    CHECK_EQ_INT(read_file_alloc(config_path, &after, &after_length), 0);
    CHECK_EQ_INT((long)after_length, (long)before_length);
    if (before && after && before_length == after_length) {
        CHECK(memcmp(before, after, before_length) == 0);
    }
    CHECK_EQ_INT(access(state_path, F_OK), -1);
    CHECK_EQ_INT(errno, ENOENT);

    config_set_io_fault_fn(NULL);
    config_set_incarnation_generate_fn(previous_generator);
    free(after);
    free(before);
    if (saved_home) {
        CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("HOME"), 0);
    }
    free(saved_home);
    ts_rm_rf(home);
}

TEST(add_and_edit_apis_enforce_internal_immutable_incarnation_binding) {
    gitswitch_ctx_t ctx;
    gitswitch_ctx_t owned;
    account_t candidate;
    account_t edit;
    accounts_transaction_token_t token = 0U;
    config_incarnation_generate_fn previous_generator;

    memset(&ctx, 0, sizeof(ctx));
    ctx.config.default_scope = GIT_SCOPE_LOCAL;
    memset(&candidate, 0, sizeof(candidate));
    candidate.id = 9U;
    candidate.preferred_scope = GIT_SCOPE_LOCAL;
    CHECK_EQ_INT(safe_strncpy(candidate.name, "bound",
                              sizeof(candidate.name)), 0);
    CHECK_EQ_INT(safe_strncpy(candidate.email, "bound@example.test",
                              sizeof(candidate.email)), 0);
    CHECK_EQ_INT(safe_strncpy(candidate.incarnation, INCARNATION_B,
                              sizeof(candidate.incarnation)), 0);
    candidate.incarnation_persisted = true;

    incarnation_generator_calls = 0U;
    incarnation_generator_success_limit = 2U;
    previous_generator = config_set_incarnation_generate_fn(
        deterministic_incarnation_generator);
    CHECK_EQ_INT(config_add_account(&ctx, &candidate), 0);
    CHECK_EQ_INT((long)ctx.account_count, 1);
    CHECK_STR_EQ(ctx.accounts[0].incarnation, INCARNATION_A);
    CHECK(!ctx.accounts[0].incarnation_persisted);
    CHECK_STR_EQ(candidate.incarnation, INCARNATION_B);
    CHECK(candidate.incarnation_persisted);

    edit = ctx.accounts[0];
    CHECK_EQ_INT(safe_strncpy(edit.description, "stale edit",
                              sizeof(edit.description)), 0);
    CHECK_EQ_INT(safe_strncpy(edit.incarnation, INCARNATION_B,
                              sizeof(edit.incarnation)), 0);
    errno = 0;
    CHECK_EQ_INT(config_update_account(&ctx, &edit), -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK_STR_EQ(ctx.accounts[0].incarnation, INCARNATION_A);
    CHECK(strcmp(ctx.accounts[0].description, "stale edit") != 0);

    edit = ctx.accounts[0];
    secure_zero_memory(edit.incarnation, sizeof(edit.incarnation));
    edit.incarnation_persisted = false;
    CHECK_EQ_INT(safe_strncpy(edit.description, "legacy-shaped edit",
                              sizeof(edit.description)), 0);
    CHECK_EQ_INT(config_update_account(&ctx, &edit), 0);
    CHECK_STR_EQ(ctx.accounts[0].incarnation, INCARNATION_A);
    CHECK_STR_EQ(ctx.accounts[0].description, "legacy-shaped edit");

    CHECK_EQ_INT(config_remove_account(&ctx, candidate.id), 0);
    CHECK_EQ_INT(config_add_account(&ctx, &candidate), 0);
    CHECK_STR_EQ(ctx.accounts[0].incarnation, INCARNATION_B);
    CHECK(!ctx.accounts[0].incarnation_persisted);

    memset(&owned, 0, sizeof(owned));
    owned.config.default_scope = GIT_SCOPE_LOCAL;
    incarnation_generator_calls = 0U;
    incarnation_generator_success_limit = 1U;
    CHECK_EQ_INT(accounts_transaction_begin(
                     &owned, ACCOUNTS_TRANSACTION_ADD, &token), 0);
    CHECK(token != 0U);
    CHECK_EQ_INT(config_add_account_owned(&owned, &candidate, token), 0);
    CHECK_STR_EQ(owned.accounts[0].incarnation, INCARNATION_A);
    CHECK(!owned.accounts[0].incarnation_persisted);
    CHECK_EQ_INT(accounts_transaction_finish(
                     &owned, ACCOUNTS_TRANSACTION_ADD, token), 0);

    config_set_incarnation_generate_fn(previous_generator);
}

TEST(malformed_publication_never_falls_back_to_legacy_ssh_retirement) {
    static const char malformed_state[] =
        "ssh\n"
        "active=alice\n"
        "publications=v1\n"
        "count=1\n"
        "p.0.account=41\n";
    char home[MAX_PATH_LEN];
    char config_path[MAX_PATH_LEN];
    char state_path[MAX_PATH_LEN];
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    const error_context_t *error;
    size_t cleared = 99U;
    int fd = -1;

    CHECK_EQ_INT(make_private_config_home(
                     home, sizeof(home), config_path, sizeof(config_path),
                     state_path, sizeof(state_path)), 0);
    fd = open(state_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(fd >= 0);
    if (fd < 0) goto cleanup;
    CHECK_EQ_INT((long)write(fd, malformed_state,
                             sizeof(malformed_state) - 1U),
                 (long)(sizeof(malformed_state) - 1U));
    CHECK_EQ_INT(close(fd), 0);
    fd = -1;

    fill_active_context(&ctx);
    CHECK_EQ_INT(safe_strncpy(ctx.config.config_path, config_path,
                              sizeof(ctx.config.config_path)), 0);
    ctx.accounts[0].gpg_enabled = false;
    ctx.accounts[0].gpg_signing_enabled = false;
    ctx.accounts[0].gpg_key_id[0] = '\0';
    ctx.accounts[0].ssh_enabled = true;
    CHECK_EQ_INT(safe_strncpy(ctx.accounts[0].ssh_key_path,
                              "/tmp/ar11-never-inspected-key",
                              sizeof(ctx.accounts[0].ssh_key_path)), 0);

    retirement_runner_calls = 0;
    retirement_unset_attempts = 0;
    previous_runner = run_set_runner(count_unexpected_retirement_runner);
    clear_error();
    errno = ENOENT; /* Must not masquerade as a proven missing record. */
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &ctx, &ctx.accounts[0], &cleared), -1);
    error = get_last_error();
    CHECK_EQ_INT((long)cleared, 0);
    CHECK_EQ_INT(retirement_runner_calls, 0);
    CHECK_EQ_INT(retirement_unset_attempts, 0);
    CHECK(error != NULL);
    if (error) {
        CHECK_EQ_INT(error->code, ERR_CONFIG_INVALID);
        CHECK(strstr(error->message, "Truncated publication ledger") != NULL);
        CHECK(strstr(error->message,
                     "No canonical publication provenance") == NULL);
    }
    run_set_runner(previous_runner);

cleanup:
    if (fd >= 0) close(fd);
    ts_rm_rf(home);
}

TEST(same_numeric_id_different_incarnation_is_never_live_publication_owner) {
    char home[MAX_PATH_LEN];
    char config_path[MAX_PATH_LEN];
    char state_path[MAX_PATH_LEN];
    char git_config_path[MAX_PATH_LEN];
    char *saved_home = NULL;
    const char *home_before = getenv("HOME");
    gitswitch_ctx_t ctx;
    gitswitch_ctx_t replacement;
    gitswitch_ctx_t legacy_replacement;
    gitswitch_ctx_t transient_replacement;
    gitswitch_ctx_t reloaded;
    publication_record_t record;
    publication_ledger_t ledger;
    const publication_record_t *found;
    config_resume_hint_snapshot_t snapshot = {0};
    command_runner_fn previous_runner;
    config_incarnation_generate_fn previous_generator;
    bool installed = false;
    size_t cleared = 17U;

    if (home_before) {
        saved_home = strdup(home_before);
        CHECK(saved_home != NULL);
    }
    CHECK_EQ_INT(make_private_config_home(
                     home, sizeof(home), config_path, sizeof(config_path),
                     state_path, sizeof(state_path)), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    fill_active_context(&ctx);
    CHECK_EQ_INT(config_save(&ctx, config_path), 0);
    CHECK_EQ_INT(join_path(git_config_path, sizeof(git_config_path), home,
                           "pair.gitconfig"), 0);
    CHECK_EQ_INT(create_complete_global_publication(
                     &record, ctx.accounts[0].id,
                     ctx.accounts[0].incarnation, home,
                     git_config_path), 0);
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&snapshot), 0);
    CHECK_EQ_INT(
        config_save_active_account_publication_transactional_guarded(
            &ctx, config_path, &record, &installed, &snapshot),
        0);
    CHECK(installed);
    config_resume_hint_snapshot_clear(&snapshot);

    replacement = ctx;
    snprintf(replacement.accounts[0].incarnation,
             sizeof(replacement.accounts[0].incarnation), "%s",
             INCARNATION_B);
    replacement.accounts[0].incarnation_persisted = true;
    replacement.current_account = &replacement.accounts[0];

    /* A complete PUBLISHED record for incarnation A cannot authorize either
     * retirement or status-like ownership for incarnation B, even though the
     * public integer is identical. Rejection precedes every Git subprocess. */
    retirement_runner_calls = 0;
    retirement_unset_attempts = 0;
    previous_runner = run_set_runner(count_unexpected_retirement_runner);
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &replacement, &replacement.accounts[0], &cleared), -1);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK_EQ_INT(retirement_runner_calls, 0);
    CHECK_EQ_INT(retirement_unset_attempts, 0);
    CHECK(strstr(get_last_error()->message,
                 "different incarnation") != NULL);
    run_set_runner(previous_runner);

    /* A live same-ID replacement is not a deletion and may not be normalized
     * into one. Full save rejects both a different token and a legacy-empty
     * token before entropy, state publication, backup, or document install.
     * The original A account and its PUBLISHED record remain one binding. */
    incarnation_generator_calls = 0U;
    incarnation_generator_success_limit = 1U;
    previous_generator = config_set_incarnation_generate_fn(
        deterministic_incarnation_generator);
    errno = 0;
    CHECK_EQ_INT(config_save(&replacement, config_path), -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK_EQ_INT((long)incarnation_generator_calls, 0);

    legacy_replacement = ctx;
    secure_zero_memory(legacy_replacement.accounts[0].incarnation,
                       sizeof(legacy_replacement.accounts[0].incarnation));
    legacy_replacement.accounts[0].incarnation_persisted = false;
    legacy_replacement.current_account = &legacy_replacement.accounts[0];
    errno = 0;
    CHECK_EQ_INT(config_save(&legacy_replacement, config_path), -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK_EQ_INT((long)incarnation_generator_calls, 0);

    transient_replacement = ctx;
    transient_replacement.accounts[0].incarnation_persisted = false;
    transient_replacement.current_account =
        &transient_replacement.accounts[0];
    errno = 0;
    CHECK_EQ_INT(config_save(&transient_replacement, config_path), -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK_EQ_INT((long)incarnation_generator_calls, 0);
    config_set_incarnation_generate_fn(previous_generator);

    publication_ledger_init(&ledger);
    CHECK_EQ_INT(config_load_publication_ledger(config_path, &ledger), 0);
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ledger, ctx.accounts[0].id, INCARNATION_A,
                     PUBLICATION_SCOPE_GLOBAL, git_config_path, "", &found),
                 PUBLICATION_LOOKUP_FOUND);
    CHECK(found != NULL);
    if (found) CHECK_EQ_INT(found->state, PUBLICATION_STATE_PUBLISHED);
    publication_ledger_clear(&ledger);

    memset(&reloaded, 0, sizeof(reloaded));
    CHECK_EQ_INT(config_init_names(&reloaded), 0);
    CHECK_EQ_INT((long)reloaded.account_count, 1);
    CHECK_STR_EQ(reloaded.accounts[0].incarnation, INCARNATION_A);
    CHECK(reloaded.accounts[0].incarnation_persisted);

    config_set_io_fault_fn(NULL);
    config_resume_hint_snapshot_clear(&snapshot);
    if (saved_home) {
        CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("HOME"), 0);
    }
    free(saved_home);
    ts_rm_rf(home);
}

TEST(removed_account_publication_reserves_recycled_id_without_git_mutation) {
    char home[MAX_PATH_LEN];
    char config_path[MAX_PATH_LEN];
    char state_path[MAX_PATH_LEN];
    char git_config_path[MAX_PATH_LEN];
    char expected_section[64];
    char *saved_home = NULL;
    char *saved_git_config_global = NULL;
    const char *home_before = getenv("HOME");
    const char *git_config_global_before = getenv("GIT_CONFIG_GLOBAL");
    gitswitch_ctx_t ctx;
    gitswitch_ctx_t forced_reuse;
    account_t removed;
    account_t edited;
    account_t replacement;
    publication_record_t record;
    publication_ledger_t ledger;
    const publication_record_t *found;
    config_resume_hint_snapshot_t snapshot = {0};
    unsigned char *config_bytes = NULL;
    size_t config_length = 0U;
    command_runner_fn previous_runner;
    bool installed = false;
    size_t cleared = 123U;

    if (home_before) {
        saved_home = strdup(home_before);
        CHECK(saved_home != NULL);
    }
    if (git_config_global_before) {
        saved_git_config_global = strdup(git_config_global_before);
        CHECK(saved_git_config_global != NULL);
    }
    CHECK_EQ_INT(make_private_config_home(
                     home, sizeof(home), config_path, sizeof(config_path),
                     state_path, sizeof(state_path)), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    fill_active_context(&ctx);
    CHECK_EQ_INT(config_save(&ctx, config_path), 0);
    removed = ctx.accounts[0];

    CHECK_EQ_INT(join_path(git_config_path, sizeof(git_config_path), home,
                           "stale.gitconfig"), 0);
    CHECK_EQ_INT(create_complete_global_publication(
                     &record, removed.id, removed.incarnation, home,
                     git_config_path), 0);
    CHECK_EQ_INT(setenv("GIT_CONFIG_GLOBAL", record.config_path, 1), 0);
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&snapshot), 0);
    CHECK_EQ_INT(
        config_save_active_account_publication_transactional_guarded(
            &ctx, config_path, &record, &installed, &snapshot),
        0);
    CHECK(installed);
    config_resume_hint_snapshot_clear(&snapshot);

    /* A stale/misbound edit may not rotate authority. Source-compatible
     * callers may omit the new field, in which case the exact persisted
     * incarnation is inherited. Disable GPG through that legacy-shaped edit:
     * retirement below must still follow the record's published capabilities,
     * rather than the account's now-mutable feature flags. */
    edited = removed;
    snprintf(edited.incarnation, sizeof(edited.incarnation), "%s",
             INCARNATION_B);
    errno = 0;
    CHECK_EQ_INT(config_update_account(&ctx, &edited), -1);
    CHECK_EQ_INT(errno, ESTALE);
    CHECK_STR_EQ(ctx.accounts[0].incarnation, INCARNATION_A);
    CHECK(ctx.accounts[0].incarnation_persisted);

    edited = removed;
    secure_zero_memory(edited.incarnation, sizeof(edited.incarnation));
    edited.incarnation_persisted = false;
    edited.gpg_enabled = false;
    edited.gpg_signing_enabled = false;
    edited.gpg_key_id[0] = '\0';
    CHECK_EQ_INT(config_update_account(&ctx, &edited), 0);
    CHECK_STR_EQ(ctx.accounts[0].incarnation, INCARNATION_A);
    CHECK(ctx.accounts[0].incarnation_persisted);
    CHECK(!ctx.accounts[0].gpg_enabled);
    removed = ctx.accounts[0];

    /* Model the removal path's best-effort retirement failure after complete
     * M8 provenance admission. The runner exposes the exact published signing
     * key, then fails the unset before changing its modeled state. Reaching
     * that unset proves this same record authorizes retirement while it is
     * PUBLISHED; the later rejection must therefore come from the committed
     * RETIRING transition, not an independently incomplete record. */
    retirement_runner_calls = 0;
    retirement_unset_attempts = 0;
    retirement_signing_key_present = true;
    CHECK_EQ_INT(safe_strncpy(retirement_expected_config_path,
                              record.config_path,
                              sizeof(retirement_expected_config_path)), 0);
    CHECK_EQ_INT(safe_strncpy(retirement_expected_gpg_program,
                              record.gpg_program,
                              sizeof(retirement_expected_gpg_program)), 0);
    previous_runner = run_set_runner(count_unexpected_retirement_runner);
    cleared = 123U;
    CHECK_EQ_INT(accounts_retire_git_identity(&ctx, &removed, &cleared), -1);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK(retirement_runner_calls > 0);
    CHECK_EQ_INT(retirement_unset_attempts, 1);
    CHECK(retirement_signing_key_present);
    CHECK(strstr(get_last_error()->message,
                 "Failed to remove exact Git config") != NULL);

    /* Account-model deletion then commits through the ordinary full-save
     * transaction. Its paired state save must retain the provenance record as
     * a non-authorizing tombstone. */
    ctx.config.active_account[0] = '\0';
    ctx.current_account = NULL;
    CHECK_EQ_INT(config_remove_account(&ctx, removed.id), 0);

    /* The state tombstone is installed before accounts.toml. If the model
     * publication then fails, the exact PUBLISHED before-image and the still-
     * present account document must both survive so a retry retains authority. */
    publication_fault_target = CONFIG_IO_DOCUMENT_BEFORE_RENAME;
    config_set_io_fault_fn(fail_publication_boundary);
    CHECK_EQ_INT(config_save(&ctx, config_path), -1);
    config_set_io_fault_fn(NULL);
    publication_ledger_init(&ledger);
    CHECK_EQ_INT(config_load_publication_ledger(config_path, &ledger), 0);
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ledger, removed.id, removed.incarnation,
                     PUBLICATION_SCOPE_GLOBAL, git_config_path, "", &found),
                 PUBLICATION_LOOKUP_FOUND);
    CHECK(found != NULL);
    if (found) CHECK_EQ_INT(found->state, PUBLICATION_STATE_PUBLISHED);
    publication_ledger_clear(&ledger);
    CHECK_EQ_INT(read_file_alloc(config_path, &config_bytes,
                                 &config_length), 0);
    CHECK(config_length > 0U);
    if (config_bytes) {
        CHECK(snprintf(expected_section, sizeof(expected_section),
                       "[accounts.%u]", removed.id) > 0);
        CHECK(strstr((const char *)config_bytes, expected_section) != NULL);
        free(config_bytes);
        config_bytes = NULL;
    }

    CHECK_EQ_INT(config_save(&ctx, config_path), 0);
    CHECK_EQ_INT((long)ctx.account_count, 0);

    publication_ledger_init(&ledger);
    CHECK_EQ_INT(config_load_publication_ledger(config_path, &ledger), 0);
    CHECK_LOOKUP_STATUS(publication_ledger_find(
                     &ledger, removed.id, removed.incarnation,
                     PUBLICATION_SCOPE_GLOBAL, git_config_path, "", &found),
                 PUBLICATION_LOOKUP_FOUND);
    CHECK(found != NULL);
    if (found) {
        CHECK_EQ_INT(found->state, PUBLICATION_STATE_RETIRING);
    }
    publication_ledger_clear(&ledger);

    replacement = removed;
    snprintf(replacement.incarnation, sizeof(replacement.incarnation), "%s",
             INCARNATION_B);
    replacement.incarnation_persisted = true;
    snprintf(replacement.name, sizeof(replacement.name), "%s", "replacement");
    snprintf(replacement.email, sizeof(replacement.email), "%s",
             "replacement@example.test");
    replacement.gpg_enabled = false;
    replacement.gpg_signing_enabled = false;
    replacement.gpg_key_id[0] = '\0';
    CHECK_EQ_INT(config_add_account(&ctx, &replacement), -1);
    CHECK_EQ_INT((long)ctx.account_count, 0);
    CHECK(strstr(get_last_error()->message,
                 "reserved by durable Git publication provenance") != NULL);

    /* Even a caller that bypasses the supported add boundary by fabricating
     * a same-ID context cannot turn the tombstone back into published
     * authority. The stale Git state remains completely untouched. */
    forced_reuse = ctx;
    forced_reuse.accounts[0] = replacement;
    forced_reuse.accounts[0].gpg_enabled = true;
    forced_reuse.accounts[0].gpg_signing_enabled = true;
    snprintf(forced_reuse.accounts[0].gpg_key_id,
             sizeof(forced_reuse.accounts[0].gpg_key_id), "%s", "22223333");
    forced_reuse.account_count = 1;
    retirement_runner_calls = 0;
    retirement_unset_attempts = 0;
    cleared = 123U;
    CHECK_EQ_INT(accounts_retire_git_identity(
                     &forced_reuse, &forced_reuse.accounts[0], &cleared), -1);
    CHECK_EQ_INT((long)cleared, 0);
    CHECK_EQ_INT(retirement_runner_calls, 0);

    replacement.id++;
    CHECK_EQ_INT(config_add_account(&ctx, &replacement), 0);
    CHECK_EQ_INT((long)ctx.account_count, 1);
    CHECK_EQ_INT(retirement_runner_calls, 0);
    run_set_runner(previous_runner);

    config_resume_hint_snapshot_clear(&snapshot);
    free(config_bytes);
    if (saved_home) {
        CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("HOME"), 0);
    }
    if (saved_git_config_global) {
        CHECK_EQ_INT(setenv("GIT_CONFIG_GLOBAL", saved_git_config_global, 1),
                     0);
    } else {
        CHECK_EQ_INT(unsetenv("GIT_CONFIG_GLOBAL"), 0);
    }
    free(saved_git_config_global);
    free(saved_home);
    ts_rm_rf(home);
}

/* AR-12 H2: only PUBLISHED records with provably dead destinations (ENOENT
 * or changed object identity on the recorded anchor) are reclaimable.
 * RETIRING residue and indeterminate probes must survive reclamation. */
TEST(reclaim_absent_drops_only_provably_dead_published_records) {
    publication_ledger_t ledger;
    publication_record_t record;
    publication_record_t dead_probe;
    char dead_repo[] = "/tmp/ar12-h2-dead-XXXXXX";
    char live_repo[] = "/tmp/ar12-h2-live-XXXXXX";
    char mismatch_repo[] = "/tmp/ar12-h2-mismatch-XXXXXX";
    char unmount_repo[] = "/tmp/ar12-h2-unmount-XXXXXX";
    char retiring_repo[] = "/tmp/ar12-h2-retiring-XXXXXX";
    struct stat st;

    CHECK(ts_mkdtemp(dead_repo) != NULL);
    CHECK(ts_mkdtemp(live_repo) != NULL);
    CHECK(ts_mkdtemp(mismatch_repo) != NULL);
    CHECK(ts_mkdtemp(unmount_repo) != NULL);
    CHECK(ts_mkdtemp(retiring_repo) != NULL);
    publication_ledger_init(&ledger);

    /* Dead destination: real identity captured, directory then removed. */
    fill_gpg_record(&record, dead_repo, FINGERPRINT_A);
    snprintf(record.config_path, sizeof(record.config_path),
             "%s/.git/config", dead_repo);
    CHECK_EQ_INT(stat(dead_repo, &st), 0);
    publication_identity_from_stat(&record.repository, &st);
    CHECK_EQ_INT(publication_ledger_upsert(&ledger, &record), 0);
    dead_probe = record;

    /* Live destination with the real identity: must be kept. */
    fill_gpg_record(&record, live_repo, FINGERPRINT_A);
    snprintf(record.config_path, sizeof(record.config_path),
             "%s/.git/config", live_repo);
    CHECK_EQ_INT(stat(live_repo, &st), 0);
    publication_identity_from_stat(&record.repository, &st);
    CHECK_EQ_INT(publication_ledger_upsert(&ledger, &record), 0);

    /* AR-13 R1: live path whose recorded identity changed ON THE SAME
     * filesystem (same st_dev, different inode) is an in-place replacement —
     * provably non-matchable, so reclaimable. */
    fill_gpg_record(&record, mismatch_repo, FINGERPRINT_A);
    snprintf(record.config_path, sizeof(record.config_path),
             "%s/.git/config", mismatch_repo);
    CHECK_EQ_INT(stat(mismatch_repo, &st), 0);
    publication_identity_from_stat(&record.repository, &st);
    record.repository.inode ^= UINTMAX_C(1); /* same device, wrong inode */
    CHECK_EQ_INT(publication_ledger_upsert(&ledger, &record), 0);

    /* AR-13 R1: live path whose recorded identity differs on a DIFFERENT
     * device is indeterminate — an unmounted volume presents its mountpoint
     * with the parent filesystem's device — so it must be KEPT (fail closed),
     * not silently reclaimed with its PUBLISHED provenance. */
    fill_gpg_record(&record, unmount_repo, FINGERPRINT_A);
    snprintf(record.config_path, sizeof(record.config_path),
             "%s/.git/config", unmount_repo);
    CHECK_EQ_INT(stat(unmount_repo, &st), 0);
    publication_identity_from_stat(&record.repository, &st);
    record.repository.device += UINTMAX_C(1); /* different device */
    record.repository.inode ^= UINTMAX_C(1);
    CHECK_EQ_INT(publication_ledger_upsert(&ledger, &record), 0);

    /* Dead destination in RETIRING state: retirement recovery owns it. */
    fill_gpg_record(&record, retiring_repo, FINGERPRINT_A);
    snprintf(record.config_path, sizeof(record.config_path),
             "%s/.git/config", retiring_repo);
    CHECK_EQ_INT(stat(retiring_repo, &st), 0);
    publication_identity_from_stat(&record.repository, &st);
    record.state = PUBLICATION_STATE_RETIRING;
    CHECK_EQ_INT(publication_ledger_upsert(&ledger, &record), 0);

    CHECK_EQ_INT(rmdir(dead_repo), 0);
    CHECK_EQ_INT(rmdir(retiring_repo), 0);
    CHECK(!publication_record_destination_provably_absent(NULL));
    CHECK(publication_record_destination_provably_absent(&dead_probe));

    /* Reclaimed: dead (deleted on the recorded fs) + same-device mismatch.
     * Kept: live, the different-device "unmount" mismatch, and RETIRING. */
    CHECK_EQ_INT((long)publication_ledger_reclaim_absent(&ledger), 2);
    CHECK_EQ_INT((long)ledger.count, 3);
    CHECK(!publication_ledger_destination_present(&ledger, &dead_probe));
    {
        bool saw_unmount = false;
        for (size_t i = 0U; i < ledger.count; i++) {
            CHECK(strstr(ledger.records[i].repository_path,
                         "ar12-h2-mismatch") == NULL);
            if (strstr(ledger.records[i].repository_path,
                       "ar12-h2-unmount") != NULL) {
                saw_unmount = true;
            }
        }
        CHECK(saw_unmount); /* different-device change failed closed */
    }

    publication_ledger_clear(&ledger);
    (void)rmdir(live_repo);
    (void)rmdir(mismatch_repo);
    (void)rmdir(unmount_repo);
}

/* AR-13 L42: R1/R2 made the oracle probe the config_parent anchor too, but the
 * reclaim test above drives only the repository anchor (config_parent left
 * synthetic device=17), so the config_parent ENOENT walk-up had no real
 * coverage. Prove both directions with real captured identities on a
 * config-parent-only (global) record: a parent removed above a surviving
 * same-device ancestor directory is provably DEAD, while an ancestor replaced
 * by a regular file makes the leaf probe fail with ENOTDIR — indeterminate, so
 * the record must be KEPT (fail closed). ENOTDIR is not privilege-bypassable,
 * so this is deterministic on every CI platform including the root FreeBSD VM,
 * unlike a chmod/EACCES construction. */
TEST(config_parent_anchor_is_dead_on_dir_ancestor_but_fails_closed_on_nondir) {
    char root[] = "/tmp/ar13-l42-XXXXXX";
    publication_record_t record;
    char sub[MAX_PATH_LEN];
    char leafdir[MAX_PATH_LEN];
    struct stat st;
    int fd;

    CHECK(ts_mkdtemp(root) != NULL);
    CHECK((size_t)snprintf(sub, sizeof(sub), "%s/sub", root) < sizeof(sub));
    CHECK((size_t)snprintf(leafdir, sizeof(leafdir), "%s/leaf", sub) <
          sizeof(leafdir));
    CHECK_EQ_INT(mkdir(sub, 0700), 0);
    CHECK_EQ_INT(mkdir(leafdir, 0700), 0);

    /* Config-parent-only record: repository anchor cleared so the oracle's
     * verdict is driven solely by the config_parent walk-up. */
    fill_gpg_record(&record, "/unused", FINGERPRINT_A);
    record.scope = PUBLICATION_SCOPE_GLOBAL;
    record.repository_path[0] = '\0';
    memset(&record.repository, 0, sizeof(record.repository));
    CHECK((size_t)snprintf(record.config_path, sizeof(record.config_path),
                           "%s/config", leafdir) < sizeof(record.config_path));
    CHECK_EQ_INT(stat(leafdir, &st), 0);
    publication_identity_from_stat(&record.config_parent, &st);

    /* Parent gone, same-device ancestor directory survives: provably DEAD. */
    CHECK_EQ_INT(rmdir(leafdir), 0);
    CHECK(publication_record_destination_provably_absent(&record));

    /* Recreate and re-capture, then replace the <root>/sub ancestor with a
     * regular file: the leaf lstat now returns ENOTDIR (not ENOENT), which is
     * indeterminate and must fail closed. */
    CHECK_EQ_INT(mkdir(leafdir, 0700), 0);
    CHECK_EQ_INT(stat(leafdir, &st), 0);
    publication_identity_from_stat(&record.config_parent, &st);
    CHECK_EQ_INT(rmdir(leafdir), 0);
    CHECK_EQ_INT(rmdir(sub), 0);
    fd = open(sub, O_WRONLY | O_CREAT | O_EXCL, 0600);
    CHECK(fd >= 0);
    if (fd >= 0) CHECK_EQ_INT(close(fd), 0);
    CHECK(!publication_record_destination_provably_absent(&record));

    (void)unlink(sub);
    (void)rmdir(root);
}

/* AR-13 R2: an in-place .git rebuild (rm -rf .git && git init) changes the
 * .git directory's inode while the worktree root is untouched. The config
 * parent is one of the identities same_destination() compares, so the record
 * can never match again and must be reclaimable. The old oracle probed only
 * the repository anchor for local records, kept such records forever, and
 * would eventually exhaust the 128-slot ledger. */
/* AR-13 L44: the AR-12 L16/L17 ledger-parse tightenings (named errors for the
 * capability-mask length and the count line; '-' as the ONLY canonical empty
 * spelling for gpg_fingerprint/gpg_selector) had zero coverage. Serialize a
 * valid record, then splice each field to its rejected form and assert the
 * named message — an any-error-to-bare--1 regression would otherwise pass. */
TEST(ledger_parse_rejects_l16_l17_grammar_tightenings) {
    publication_ledger_t source, loaded;
    publication_record_t record;
    unsigned char *serialized = NULL;
    size_t serialized_length = 0U;
    struct {
        const char *prefix;
        const char *replacement;
        const char *msg;
    } cases[] = {
        {"p.0.gpg_fingerprint=", "",
         "Empty publication gpg_fingerprint requires '-'"},
        {"p.0.gpg_selector=", "",
         "Empty publication gpg_selector requires '-'"},
        {"p.0.capabilities=", "1234567",
         "Invalid publication capability mask length"},
        {"p.0.capabilities=", "123456789",
         "Invalid publication capability mask length"},
    };

    fill_gpg_record(&record, "/tmp/ar13-l44-repo", FINGERPRINT_A);
    publication_ledger_init(&source);
    CHECK_EQ_INT(publication_record_validate(&record), 0);
    CHECK_EQ_INT(publication_ledger_upsert(&source, &record), 0);
    CHECK_EQ_INT(publication_ledger_serialize(&source, &serialized,
                                              &serialized_length), 0);
    CHECK(serialized != NULL);

    for (size_t i = 0U; i < sizeof(cases) / sizeof(cases[0]); i++) {
        unsigned char *bad = NULL;
        size_t bad_length = 0U;

        bad = replace_serialized_field_value(serialized, serialized_length,
                                             cases[i].prefix,
                                             cases[i].replacement, &bad_length);
        CHECK(bad != NULL);
        publication_ledger_init(&loaded);
        clear_error();
        CHECK_EQ_INT(publication_ledger_parse(bad, bad_length, &loaded), -1);
        CHECK(strstr(get_last_error()->message, cases[i].msg) != NULL);
        free(bad);
        publication_ledger_clear(&loaded);
    }

    /* Removing the count line leaves a non-'count=' line where the count is
     * expected -> the named malformed-count-line rejection. */
    {
        unsigned char *bad = NULL;
        size_t bad_length = 0U;

        bad = remove_serialized_field_line(serialized, serialized_length,
                                           "count=", &bad_length);
        CHECK(bad != NULL);
        publication_ledger_init(&loaded);
        clear_error();
        CHECK_EQ_INT(publication_ledger_parse(bad, bad_length, &loaded), -1);
        CHECK(strstr(get_last_error()->message,
                     "Malformed publication ledger count line") != NULL);
        free(bad);
        publication_ledger_clear(&loaded);
    }

    free(serialized);
    publication_ledger_clear(&source);
}

TEST(reclaim_absent_drops_local_record_after_in_place_git_rebuild) {
    publication_ledger_t ledger;
    publication_record_t record;
    char repo[] = "/tmp/ar13-r2-repo-XXXXXX";
    char gitdir[sizeof(repo) + 8];
    struct stat st;

    CHECK(ts_mkdtemp(repo) != NULL);
    snprintf(gitdir, sizeof(gitdir), "%s/.git", repo);
    CHECK_EQ_INT(mkdir(gitdir, 0700), 0);
    publication_ledger_init(&ledger);

    fill_gpg_record(&record, repo, FINGERPRINT_A);
    snprintf(record.config_path, sizeof(record.config_path), "%s/.git/config",
             repo);
    CHECK_EQ_INT(stat(gitdir, &st), 0);
    publication_identity_from_stat(&record.config_parent, &st);
    CHECK_EQ_INT(stat(repo, &st), 0);
    publication_identity_from_stat(&record.repository, &st);
    CHECK_EQ_INT(publication_ledger_upsert(&ledger, &record), 0);

    /* All anchors live and matching: not reclaimable. */
    CHECK(!publication_record_destination_provably_absent(&ledger.records[0]));

    /* An in-place `rm -rf .git && git init` leaves the worktree root untouched
     * but gives .git a new inode on the SAME filesystem. Simulate that exact
     * state deterministically by staling only the recorded config_parent inode
     * (a real rmdir+mkdir can reuse the freed inode on ext4/UFS, leaving the
     * identity unchanged). The live .git still exists, so the config-parent
     * anchor reads present-but-different-object on the same device -> provably
     * dead, while the repository anchor stays live. */
    ledger.records[0].config_parent.inode ^= UINTMAX_C(1);

    CHECK(publication_record_destination_provably_absent(&ledger.records[0]));
    CHECK_EQ_INT((long)publication_ledger_reclaim_absent(&ledger), 1);
    CHECK_EQ_INT((long)ledger.count, 0);

    publication_ledger_clear(&ledger);
    (void)rmdir(gitdir);
    (void)rmdir(repo);
}

/* AR-12 H2: a full 128-record ledger must still admit a switch whose
 * destination already has a record (in-place replacement), and must reclaim
 * provably dead destinations rather than deterministically blocking every
 * new destination for the config's lifetime. */
TEST(at_capacity_ledger_admits_replacement_and_reclaims_dead_destinations) {
    char home[MAX_PATH_LEN];
    char config_path[MAX_PATH_LEN];
    char state_path[MAX_PATH_LEN];
    char git_config_path[MAX_PATH_LEN];
    char dead_repo[MAX_PATH_LEN];
    char *saved_home = NULL;
    const char *home_before = getenv("HOME");
    gitswitch_ctx_t ctx;
    publication_record_t record;
    publication_record_t probe;
    publication_ledger_t ledger;
    config_resume_hint_snapshot_t snapshot = {0};
    struct stat home_stat;
    struct stat repo_stat;
    bool installed = false;

    if (home_before) {
        saved_home = strdup(home_before);
        CHECK(saved_home != NULL);
    }
    CHECK_EQ_INT(make_private_config_home(
                     home, sizeof(home), config_path, sizeof(config_path),
                     state_path, sizeof(state_path)), 0);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    fill_active_context(&ctx);
    CHECK_EQ_INT(config_save(&ctx, config_path), 0);
    CHECK_EQ_INT(stat(home, &home_stat), 0);
    CHECK_EQ_INT(join_path(dead_repo, sizeof(dead_repo), home,
                           "doomed-repository"), 0);
    CHECK_EQ_INT(mkdir(dead_repo, 0700), 0);
    CHECK_EQ_INT(stat(dead_repo, &repo_stat), 0);

    /* Record 0 is a local destination in a repository that will later be
     * deleted; records 1..127 are live global destinations under HOME. */
    fill_gpg_record(&record, dead_repo, FINGERPRINT_A);
    CHECK_EQ_INT(safe_snprintf(record.config_path,
                               sizeof(record.config_path),
                               "%s/.git/config", dead_repo), 0);
    publication_identity_from_stat(&record.repository, &repo_stat);
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&snapshot), 0);
    installed = false;
    CHECK_EQ_INT(
        config_save_active_account_publication_transactional_guarded(
            &ctx, config_path, &record, &installed, &snapshot), 0);
    CHECK(installed);
    config_resume_hint_snapshot_clear(&snapshot);
    for (size_t i = 1U; i < PUBLICATION_LEDGER_MAX_RECORDS; i++) {
        char leaf[64];

        snprintf(leaf, sizeof(leaf), "global-%03zu.gitconfig", i);
        CHECK_EQ_INT(join_path(git_config_path, sizeof(git_config_path),
                               home, leaf), 0);
        fill_global_gpg_record(&record, UINT32_C(41), git_config_path,
                               FINGERPRINT_A);
        publication_identity_from_stat(&record.config_parent, &home_stat);
        CHECK_EQ_INT(config_resume_hint_snapshot_capture(&snapshot), 0);
        installed = false;
        CHECK_EQ_INT(
            config_save_active_account_publication_transactional_guarded(
                &ctx, config_path, &record, &installed, &snapshot), 0);
        CHECK(installed);
        config_resume_hint_snapshot_clear(&snapshot);
    }
    publication_ledger_init(&ledger);
    CHECK_EQ_INT(config_load_publication_ledger(config_path, &ledger), 0);
    CHECK_EQ_INT((long)ledger.count,
                 (long)PUBLICATION_LEDGER_MAX_RECORDS);
    publication_ledger_clear(&ledger);

    /* Conservative append preflight: full and fully live -> no capacity. */
    errno = 0;
    CHECK_EQ_INT(config_publication_preflight(config_path), -1);
    CHECK_EQ_INT(errno, ENOSPC);

    /* A destination that already has a record is a replacement. */
    CHECK_EQ_INT(join_path(git_config_path, sizeof(git_config_path), home,
                           "global-005.gitconfig"), 0);
    fill_global_gpg_record(&probe, UINT32_C(41), git_config_path,
                           FINGERPRINT_A);
    publication_identity_from_stat(&probe.config_parent, &home_stat);
    CHECK_EQ_INT(config_publication_preflight_destination(
                     config_path, &probe), 0);

    /* A genuinely new destination is still refused while every recorded
     * destination remains alive... */
    CHECK_EQ_INT(join_path(git_config_path, sizeof(git_config_path), home,
                           "global-new.gitconfig"), 0);
    fill_global_gpg_record(&probe, UINT32_C(41), git_config_path,
                           FINGERPRINT_A);
    publication_identity_from_stat(&probe.config_parent, &home_stat);
    errno = 0;
    CHECK_EQ_INT(config_publication_preflight_destination(
                     config_path, &probe), -1);
    CHECK_EQ_INT(errno, ENOSPC);

    /* ...but once a recorded repository is provably gone, both the
     * preflight and the durable save reclaim it. */
    CHECK_EQ_INT(rmdir(dead_repo), 0);
    CHECK_EQ_INT(config_publication_preflight_destination(
                     config_path, &probe), 0);
    record = probe;
    CHECK_EQ_INT(config_resume_hint_snapshot_capture(&snapshot), 0);
    installed = false;
    CHECK_EQ_INT(
        config_save_active_account_publication_transactional_guarded(
            &ctx, config_path, &record, &installed, &snapshot), 0);
    CHECK(installed);
    config_resume_hint_snapshot_clear(&snapshot);
    publication_ledger_init(&ledger);
    CHECK_EQ_INT(config_load_publication_ledger(config_path, &ledger), 0);
    CHECK_EQ_INT((long)ledger.count,
                 (long)PUBLICATION_LEDGER_MAX_RECORDS);
    CHECK(publication_ledger_destination_present(&ledger, &probe));
    for (size_t i = 0U; i < ledger.count; i++) {
        CHECK(strstr(ledger.records[i].repository_path,
                     "doomed-repository") == NULL);
    }
    publication_ledger_clear(&ledger);

    if (saved_home) {
        CHECK_EQ_INT(setenv("HOME", saved_home, 1), 0);
    } else {
        CHECK_EQ_INT(unsetenv("HOME"), 0);
    }
    free(saved_home);
    ts_rm_rf(home);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(empty_tail_is_an_explicit_legacy_ledger_absence);
    RUN_TEST(gpg_selector_normalization_canonicalizes_case_prefix_and_v5_boundary);
    RUN_TEST(gpg_selector_record_validation_requires_complete_canonical_tuple);
    RUN_TEST(ssh_program_extraction_accepts_only_the_managed_first_word);
    RUN_TEST(ssh_record_validation_requires_complete_matching_provenance);
    RUN_TEST(complete_ssh_tuple_round_trip_preserves_exact_record);
    RUN_TEST(complete_gpg_selector_tuple_round_trip_preserves_exact_record);
    RUN_TEST(legacy_gpg_pair_without_selector_field_remains_retirement_compatible);
    RUN_TEST(gpg_signing_state_true_and_false_round_trip_canonically);
    RUN_TEST(legacy_gpg_signing_state_absence_remains_compatible);
    RUN_TEST(gpg_signing_state_validation_requires_capability_and_gpg_witnesses);
    RUN_TEST(persisted_gpg_signing_state_rejects_malformed_fields_and_order);
    RUN_TEST(persisted_gpg_selector_schema_rejects_malformed_fields_and_tuples);
    RUN_TEST(publication_lookup_distinguishes_absence_from_invalid_or_ambiguous_data);
    RUN_TEST(raw_incarnation_uniformity_includes_skipped_and_rejected_accounts);
    RUN_TEST(publication_parser_requires_one_canonical_account_incarnation);
    RUN_TEST(identity_parser_rejects_malformed_overflow_and_noncanonical_numbers);
    RUN_TEST(serializer_rejects_duplicate_publication_destinations);
    RUN_TEST(upsert_replaces_only_the_exact_publication_destination);
    RUN_TEST(destination_aliases_share_one_canonical_upsert_lookup_and_live_key);
    RUN_TEST(absent_config_leaf_uses_anchored_parent_but_conflicts_stay_unresolved);
    RUN_TEST(offline_destination_spellings_round_trip_without_ancestry_rewrite);
    RUN_TEST(alias_duplicate_destinations_fail_closed_in_serializer_and_parser);
    RUN_TEST(upsert_rejects_offline_aliases_that_converge_without_model_mutation);
    RUN_TEST(guarded_publication_clears_install_state_before_input_validation);
    RUN_TEST(guarded_publication_requires_the_exact_live_active_incarnation);
    RUN_TEST(guarded_publication_preserves_intervening_writer_generation);
    RUN_TEST(active_state_bundle_round_trip_and_failed_save_restore_old_ledger);
    RUN_TEST(legacy_read_is_observational_and_migration_binds_all_accounts_once);
    RUN_TEST(migration_failure_restores_file_state_and_exact_in_memory_before_image);
    RUN_TEST(add_and_edit_apis_enforce_internal_immutable_incarnation_binding);
    RUN_TEST(malformed_publication_never_falls_back_to_legacy_ssh_retirement);
    RUN_TEST(same_numeric_id_different_incarnation_is_never_live_publication_owner);
    RUN_TEST(removed_account_publication_reserves_recycled_id_without_git_mutation);
    RUN_TEST(reclaim_absent_drops_only_provably_dead_published_records);
    RUN_TEST(config_parent_anchor_is_dead_on_dir_ancestor_but_fails_closed_on_nondir);
    RUN_TEST(ledger_parse_rejects_l16_l17_grammar_tightenings);
    RUN_TEST(reclaim_absent_drops_local_record_after_in_place_git_rebuild);
    RUN_TEST(at_capacity_ledger_admits_replacement_and_reclaims_dead_destinations);
TEST_MAIN_END()
