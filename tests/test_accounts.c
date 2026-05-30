/* Tests for account resolution: exact-match-first, ambiguity rejection. */
#include "test.h"
#include "gitswitch.h"
#include "config.h"
#include "error.h"
#include <string.h>

static void add(gitswitch_ctx_t *ctx, uint32_t id, const char *name,
                const char *email, const char *desc) {
    account_t *a = &ctx->accounts[ctx->account_count++];
    memset(a, 0, sizeof(*a));
    a->id = id;
    strncpy(a->name, name, sizeof(a->name) - 1);
    strncpy(a->email, email, sizeof(a->email) - 1);
    strncpy(a->description, desc, sizeof(a->description) - 1);
}

static gitswitch_ctx_t base_ctx(void) {
    gitswitch_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    add(&ctx, 1, "work",        "w@x.com",     "day job");
    add(&ctx, 2, "work-backup", "wb@x.com",    "backup");
    add(&ctx, 3, "personal",    "me@home.org", "home stuff");
    return ctx;
}

TEST(find_by_numeric_id) {
    gitswitch_ctx_t ctx = base_ctx();
    account_t *a = config_find_account(&ctx, "2");
    CHECK(a != NULL);
    if (a) CHECK_EQ_INT(a->id, 2);
}

TEST(find_exact_name_beats_substring) {
    /* "work" is also a substring of "work-backup": exact name must win. */
    gitswitch_ctx_t ctx = base_ctx();
    account_t *a = config_find_account(&ctx, "work");
    CHECK(a != NULL);
    if (a) CHECK_EQ_INT(a->id, 1);
}

TEST(find_exact_email) {
    gitswitch_ctx_t ctx = base_ctx();
    account_t *a = config_find_account(&ctx, "me@home.org");
    CHECK(a != NULL);
    if (a) CHECK_EQ_INT(a->id, 3);
}

TEST(find_unambiguous_substring) {
    gitswitch_ctx_t ctx = base_ctx();
    account_t *a = config_find_account(&ctx, "backup"); /* only in work-backup */
    CHECK(a != NULL);
    if (a) CHECK_EQ_INT(a->id, 2);
}

TEST(find_ambiguous_substring_rejected) {
    /* "wor" is a substring of both "work" and "work-backup": must NOT silently
     * pick the first — return NULL (ambiguous). */
    gitswitch_ctx_t ctx = base_ctx();
    account_t *a = config_find_account(&ctx, "wor");
    CHECK(a == NULL);
}

TEST(find_not_found) {
    gitswitch_ctx_t ctx = base_ctx();
    CHECK(config_find_account(&ctx, "nonesuch") == NULL);
}

TEST(find_numeric_id_takes_precedence_over_name) {
    /* identifier "1" with an existing id 1 resolves to id 1. */
    gitswitch_ctx_t ctx = base_ctx();
    add(&ctx, 7, "1", "one@x.com", "literally named one");
    account_t *a = config_find_account(&ctx, "1");
    CHECK(a != NULL);
    if (a) CHECK_EQ_INT(a->id, 1);
}

TEST(find_name_one_reachable_without_id_one) {
    /* When no id 1 exists, the account literally named "1" is reachable. */
    gitswitch_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    add(&ctx, 7, "1", "one@x.com", "named one");
    add(&ctx, 8, "two", "two@x.com", "named two");
    account_t *a = config_find_account(&ctx, "1");
    CHECK(a != NULL);
    if (a) CHECK_EQ_INT(a->id, 7);
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(find_by_numeric_id);
    RUN_TEST(find_exact_name_beats_substring);
    RUN_TEST(find_exact_email);
    RUN_TEST(find_unambiguous_substring);
    RUN_TEST(find_ambiguous_substring_rejected);
    RUN_TEST(find_not_found);
    RUN_TEST(find_numeric_id_takes_precedence_over_name);
    RUN_TEST(find_name_one_reachable_without_id_one);
TEST_MAIN_END()
