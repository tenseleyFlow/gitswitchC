/* AR-09 M8: file-backed configuration entry points must reject nonregular
 * inputs promptly, through one pinned descriptor, and without caller mutation. */

#include "test.h"
#include "config.h"
#include "error.h"
#include "toml_parser.h"

#include <signal.h>
#include <sys/wait.h>

typedef enum {
    ENTRY_CONFIG_LOAD = 0,
    ENTRY_TOML_PARSE_FILE = 1
} file_entry_kind_t;

static void exit_on_alarm(int signal_number) {
    (void)signal_number;
    _exit(90);
}

static bool document_is_zeroed(const toml_document_t *doc) {
    const unsigned char *bytes = (const unsigned char *)doc;

    for (size_t i = 0; i < sizeof(*doc); i++) {
        if (bytes[i] != 0) return false;
    }
    return true;
}

static int exercise_config_entry(const char *path) {
    gitswitch_ctx_t *ctx = calloc(1, sizeof(*ctx));
    gitswitch_ctx_t *before = malloc(sizeof(*before));
    int result;

    if (!ctx || !before) {
        free(ctx);
        free(before);
        return 10;
    }
    ctx->account_count = 1;
    ctx->accounts[0].id = 77;
    ctx->current_account = &ctx->accounts[0];
    ctx->accounts_skipped_on_load = 3;
    ctx->unknown_sections_on_load = 4;
    ctx->unknown_keys_on_load = 5;
    memcpy(before, ctx, sizeof(*before));

    result = config_load(ctx, path);
    if (result != -1) result = 11;
    else if (memcmp(ctx, before, sizeof(*ctx)) != 0) result = 12;
    else if (strstr(get_last_error()->message, "regular file") == NULL) {
        result = 13;
    } else {
        result = 0;
    }

    free(before);
    free(ctx);
    return result;
}

static int exercise_toml_entry(const char *path) {
    toml_document_t *doc = malloc(sizeof(*doc));
    int result;

    if (!doc) return 20;
    memset(doc, 0xA5, sizeof(*doc));
    result = toml_parse_file(path, doc);
    if (result != -1) result = 21;
    else if (!document_is_zeroed(doc)) result = 22;
    else if (strstr(get_last_error()->message, "regular file") == NULL) {
        result = 23;
    } else {
        result = 0;
    }
    toml_cleanup_document(doc);
    free(doc);
    return result;
}

static int run_entry_bounded(file_entry_kind_t kind, const char *path) {
    pid_t child = fork();
    int status;
    pid_t waited;

    if (child < 0) return -1;
    if (child == 0) {
        int result;

        if (signal(SIGALRM, exit_on_alarm) == SIG_ERR) _exit(91);
        alarm(2);
        result = kind == ENTRY_CONFIG_LOAD
                     ? exercise_config_entry(path)
                     : exercise_toml_entry(path);
        alarm(0);
        _exit(result);
    }

    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

static int write_valid_toml(const char *path) {
    static const char content[] =
        "[settings]\n"
        "default_scope = \"local\"\n";
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    size_t total = 0;

    if (fd < 0) return -1;
    while (total < sizeof(content) - 1U) {
        ssize_t written = write(fd, content + total,
                                sizeof(content) - 1U - total);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) {
            close(fd);
            return -1;
        }
        total += (size_t)written;
    }
    return close(fd);
}

TEST(config_load_rejects_fifo_promptly_without_mutating_context) {
    char dir[] = "/tmp/gitswitch-ar09-config-fifo.XXXXXX";
    char path[256];

    CHECK(ts_mkdtemp(dir) != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/accounts.toml", dir) <
          sizeof(path));
    CHECK_EQ_INT(mkfifo(path, 0600), 0);
    CHECK_EQ_INT(run_entry_bounded(ENTRY_CONFIG_LOAD, path), 0);
}

TEST(public_toml_parser_rejects_fifo_promptly_and_initializes_document) {
    char dir[] = "/tmp/gitswitch-ar09-toml-fifo.XXXXXX";
    char path[256];

    CHECK(ts_mkdtemp(dir) != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/input.toml", dir) <
          sizeof(path));
    CHECK_EQ_INT(mkfifo(path, 0600), 0);
    CHECK_EQ_INT(run_entry_bounded(ENTRY_TOML_PARSE_FILE, path), 0);
}

TEST(both_entry_points_reject_directory_before_open) {
    char dir[] = "/tmp/gitswitch-ar09-entry-dir.XXXXXX";
    char path[256];

    CHECK(ts_mkdtemp(dir) != NULL);
    CHECK((size_t)snprintf(path, sizeof(path), "%s/node", dir) <
          sizeof(path));
    CHECK_EQ_INT(mkdir(path, 0700), 0);
    CHECK_EQ_INT(run_entry_bounded(ENTRY_CONFIG_LOAD, path), 0);
    CHECK_EQ_INT(run_entry_bounded(ENTRY_TOML_PARSE_FILE, path), 0);
}

TEST(both_entry_points_reject_character_device_before_open) {
    struct stat device;

    CHECK_EQ_INT(lstat("/dev/null", &device), 0);
    CHECK(S_ISCHR(device.st_mode));
    CHECK_EQ_INT(run_entry_bounded(ENTRY_CONFIG_LOAD, "/dev/null"), 0);
    CHECK_EQ_INT(run_entry_bounded(ENTRY_TOML_PARSE_FILE, "/dev/null"), 0);
}

TEST(public_toml_parser_rejects_symlink_instead_of_following_it) {
    char dir[] = "/tmp/gitswitch-ar09-toml-link.XXXXXX";
    char target[256];
    char link_path[256];
    toml_document_t *doc = malloc(sizeof(*doc));

    CHECK(doc != NULL);
    CHECK(ts_mkdtemp(dir) != NULL);
    CHECK((size_t)snprintf(target, sizeof(target), "%s/target.toml", dir) <
          sizeof(target));
    CHECK((size_t)snprintf(link_path, sizeof(link_path), "%s/link.toml", dir) <
          sizeof(link_path));
    CHECK_EQ_INT(write_valid_toml(target), 0);
    CHECK_EQ_INT(symlink(target, link_path), 0);
    if (!doc) return;

    memset(doc, 0xA5, sizeof(*doc));
    CHECK_EQ_INT(toml_parse_file(link_path, doc), -1);
    CHECK(document_is_zeroed(doc));
    CHECK(strstr(get_last_error()->message, "symlink") != NULL);
    toml_cleanup_document(doc);
    free(doc);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_CRITICAL, NULL);
    RUN_TEST(config_load_rejects_fifo_promptly_without_mutating_context);
    RUN_TEST(public_toml_parser_rejects_fifo_promptly_and_initializes_document);
    RUN_TEST(both_entry_points_reject_directory_before_open);
    RUN_TEST(both_entry_points_reject_character_device_before_open);
    RUN_TEST(public_toml_parser_rejects_symlink_instead_of_following_it);
TEST_MAIN_END()
