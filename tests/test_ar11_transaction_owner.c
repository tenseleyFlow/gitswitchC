/* AR-11 T5 M1/M2: causal tests for the process-global account transaction
 * owner. These cases deliberately avoid persistence and manager fixtures;
 * each assertion targets kind/context/token/depth/phase admission itself. */

#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include "test.h"
#include "accounts.h"
#include "config.h"
#include "error.h"
#include "signals.h"
#include "utils.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const accounts_transaction_kind_t transaction_kinds[] = {
    ACCOUNTS_TRANSACTION_INITIALIZE,
    ACCOUNTS_TRANSACTION_SWITCH,
    ACCOUNTS_TRANSACTION_ADD,
    ACCOUNTS_TRANSACTION_EDIT,
    ACCOUNTS_TRANSACTION_REMOVE,
    ACCOUNTS_TRANSACTION_RESET,
};

static void make_base_context(gitswitch_ctx_t *ctx) {
    account_t *account;

    memset(ctx, 0, sizeof(*ctx));
    ctx->config.default_scope = GIT_SCOPE_GLOBAL;
    ctx->config.assume_yes = true;
    account = &ctx->accounts[0];
    account->id = 11;
    CHECK_EQ_INT(safe_strncpy(account->name, "existing",
                              sizeof(account->name)), 0);
    CHECK_EQ_INT(safe_strncpy(account->email, "existing@example.test",
                              sizeof(account->email)), 0);
    CHECK_EQ_INT(safe_strncpy(account->description, "existing account",
                              sizeof(account->description)), 0);
    account->preferred_scope = GIT_SCOPE_GLOBAL;
    ctx->account_count = 1;
    ctx->current_account = account;
}

static account_t make_model_candidate(uint32_t id, const char *name,
                                      const char *description) {
    account_t candidate;

    memset(&candidate, 0, sizeof(candidate));
    candidate.id = id;
    CHECK_EQ_INT(safe_strncpy(candidate.name, name,
                              sizeof(candidate.name)), 0);
    CHECK_EQ_INT(safe_snprintf(candidate.email, sizeof(candidate.email),
                               "%s@example.test", name), 0);
    CHECK_EQ_INT(safe_strncpy(candidate.description, description,
                              sizeof(candidate.description)), 0);
    candidate.preferred_scope = GIT_SCOPE_GLOBAL;
    return candidate;
}

/* Feed the non-TTY add flow exactly six answers (name, email, description,
 * SSH, GPG, scope) and hide its presentation output. */
static int prepare_add_silently(gitswitch_ctx_t *ctx, const char *name,
                                const char *email) {
    char script[1024];
    FILE *input = NULL;
    FILE *capture = NULL;
    int saved_stdin = -1;
    int saved_stdout = -1;
    int rc = -2;
    int length;

    length = snprintf(script, sizeof(script), "%s\n%s\n\n\n\n\n",
                      name, email);
    if (length < 0 || (size_t)length >= sizeof(script)) return -2;
    input = tmpfile();
    capture = tmpfile();
    if (!input || !capture ||
        fwrite(script, 1, (size_t)length, input) != (size_t)length ||
        fflush(input) != 0 || fseek(input, 0, SEEK_SET) != 0) {
        goto cleanup;
    }
    saved_stdin = dup(STDIN_FILENO);
    saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdin < 0 || saved_stdout < 0 || fflush(stdout) != 0 ||
        dup2(fileno(input), STDIN_FILENO) != STDIN_FILENO ||
        dup2(fileno(capture), STDOUT_FILENO) != STDOUT_FILENO) {
        goto cleanup;
    }
    clearerr(stdin);
    rc = accounts_add_interactive_prepare(ctx);
    if (fflush(stdout) != 0) rc = -2;

cleanup:
    if (saved_stdin >= 0) {
        (void)dup2(saved_stdin, STDIN_FILENO);
        close(saved_stdin);
    }
    if (saved_stdout >= 0) {
        (void)dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }
    clearerr(stdin);
    if (input) fclose(input);
    if (capture) fclose(capture);
    return rc;
}

TEST(every_kind_pair_requires_exact_context_token_and_depth) {
    const size_t kind_count =
        sizeof(transaction_kinds) / sizeof(transaction_kinds[0]);

    CHECK_EQ_INT(signals_guard_end(), 0);
    signals_rollback_end();
    CHECK(!signals_guard_active());
    CHECK(!signals_rollback_active());

    for (size_t owner_index = 0; owner_index < kind_count; owner_index++) {
        gitswitch_ctx_t owner;
        gitswitch_ctx_t contender;
        gitswitch_ctx_t owner_before;
        gitswitch_ctx_t contender_before;
        accounts_transaction_token_t token = 0;
        accounts_transaction_token_t foreign;
        accounts_transaction_kind_t owner_kind =
            transaction_kinds[owner_index];
        accounts_transaction_kind_t wrong_kind =
            transaction_kinds[(owner_index + 1U) % kind_count];

        make_base_context(&owner);
        make_base_context(&contender);
        owner_before = owner;
        contender_before = contender;
        CHECK(accounts_transaction_context_release_safe(&owner));
        CHECK(accounts_transaction_context_release_safe(&contender));
        CHECK(!accounts_transaction_context_release_safe(NULL));
        CHECK_EQ_INT(accounts_transaction_begin(&owner, owner_kind, &token),
                     0);
        if (token == 0) return;
        CHECK(!accounts_transaction_context_release_safe(&owner));
        CHECK(accounts_transaction_context_release_safe(&contender));
        foreign = token ^ UINT64_C(0x8000000000000000);
        if (foreign == 0 || foreign == token) foreign = token + 1U;

        /* Exhaust every valid owner/contender kind pair. The rejected call
         * cannot publish an output token or touch either context. */
        for (size_t contender_index = 0; contender_index < kind_count;
             contender_index++) {
            accounts_transaction_token_t rejected =
                UINT64_C(0xA5A5A5A5A5A5A5A5);

            CHECK_EQ_INT(accounts_transaction_begin(
                             &contender, transaction_kinds[contender_index],
                             &rejected), -1);
            CHECK(rejected == UINT64_C(0xA5A5A5A5A5A5A5A5));
            CHECK(memcmp(&owner, &owner_before, sizeof(owner)) == 0);
            CHECK(memcmp(&contender, &contender_before,
                         sizeof(contender)) == 0);
        }

        CHECK_EQ_INT(accounts_transaction_rollback_begin(
                         &owner, wrong_kind, token), -1);
        CHECK_EQ_INT(accounts_transaction_rollback_begin(
                         &contender, owner_kind, token), -1);
        CHECK_EQ_INT(accounts_transaction_rollback_begin(
                         &owner, owner_kind, foreign), -1);
        CHECK_EQ_INT(accounts_transaction_finish(&owner, wrong_kind, token),
                     -1);
        CHECK_EQ_INT(accounts_transaction_finish(
                         &contender, owner_kind, token), -1);
        CHECK_EQ_INT(accounts_transaction_finish(&owner, owner_kind, foreign),
                     -1);
        CHECK(!signals_rollback_active());

        CHECK_EQ_INT(accounts_transaction_rollback_begin(
                         &owner, owner_kind, token), 0);
        CHECK_EQ_INT(accounts_transaction_rollback_begin(
                         &owner, owner_kind, token), 0);
        CHECK(signals_rollback_active());

        /* Legacy idempotent ownership is independent and cannot clear the
         * checked owner's handler-visible deferral. */
        signals_rollback_begin();
        signals_rollback_end();
        CHECK(signals_rollback_active());
        CHECK_EQ_INT(signals_rollback_begin_owned(foreign), -1);
        CHECK_EQ_INT(signals_rollback_end_owned(foreign), -1);
        CHECK(signals_rollback_active());

        CHECK_EQ_INT(accounts_transaction_rollback_end(
                         &owner, wrong_kind, token), -1);
        CHECK_EQ_INT(accounts_transaction_rollback_end(
                         &contender, owner_kind, token), -1);
        CHECK_EQ_INT(accounts_transaction_rollback_end(
                         &owner, owner_kind, foreign), -1);
        CHECK_EQ_INT(accounts_transaction_finish(&owner, owner_kind, token),
                     -1);
        CHECK(signals_rollback_active());

        CHECK_EQ_INT(accounts_transaction_rollback_end(
                         &owner, owner_kind, token), 0);
        CHECK(signals_rollback_active());
        CHECK_EQ_INT(accounts_transaction_finish(&owner, owner_kind, token),
                     -1);
        CHECK_EQ_INT(accounts_transaction_rollback_end(
                         &owner, owner_kind, token), 0);
        CHECK(!signals_rollback_active());
        CHECK_EQ_INT(accounts_transaction_rollback_end(
                         &owner, owner_kind, token), -1);
        CHECK_EQ_INT(accounts_transaction_finish(&owner, owner_kind, token),
                     0);
        CHECK(accounts_transaction_context_release_safe(&owner));

        /* Exact finalization reopens admission and never reuses a token. */
        {
            accounts_transaction_token_t next = 0;
            CHECK_EQ_INT(accounts_transaction_begin(
                             &contender, wrong_kind, &next), 0);
            CHECK(next != 0 && next != token);
            if (next != 0) {
                CHECK_EQ_INT(accounts_transaction_finish(
                                 &contender, wrong_kind, next), 0);
            }
        }
    }
}

TEST(public_cross_type_entrypoints_and_finalizers_preserve_owner) {
    gitswitch_ctx_t owner;
    gitswitch_ctx_t contender;
    gitswitch_ctx_t owner_before;
    gitswitch_ctx_t contender_before;
    account_t candidate;
    accounts_transaction_token_t token = 0;
    accounts_transaction_token_t rejected =
        UINT64_C(0x5A5A5A5A5A5A5A5A);
    accounts_switch_prepare_state_t prepare_state =
        ACCOUNTS_SWITCH_PREPARE_ABORT_REQUIRED;
    accounts_switch_commit_state_t state =
        ACCOUNTS_SWITCH_COMMIT_ALIAS_CLEANUP_FAILED;

    make_base_context(&owner);
    make_base_context(&contender);
    candidate = contender.accounts[0];
    owner_before = owner;
    contender_before = contender;
    CHECK_EQ_INT(accounts_transaction_begin(
                     &owner, ACCOUNTS_TRANSACTION_RESET, &token), 0);
    if (token == 0) return;

    CHECK_EQ_INT(accounts_init(&owner), -1);
    CHECK_EQ_INT(accounts_init(&contender), -1);
    CHECK_EQ_INT(accounts_session_cleanup(), -1);
    CHECK_EQ_INT(accounts_switch(NULL, NULL), -1);
    CHECK_EQ_INT(accounts_switch_prepare_result(
                     &contender, NULL, &prepare_state),
                 -1);
    CHECK_EQ_INT(prepare_state, ACCOUNTS_SWITCH_PREPARE_CLEAN_FAILURE);
    CHECK_EQ_INT(accounts_add_interactive_prepare(&contender), -1);
    CHECK_EQ_INT(accounts_edit_interactive_prepare(&contender, NULL), -1);
    CHECK_EQ_INT(accounts_edit_candidate_prepare(&contender, &candidate), -1);
    CHECK_EQ_INT(accounts_remove(&contender, NULL), -1);

    CHECK_EQ_INT(accounts_switch_commit_result(&contender, &state), -1);
    CHECK_EQ_INT(state, ACCOUNTS_SWITCH_COMMIT_NOT_COMMITTED);
    CHECK_EQ_INT(accounts_switch_abort(&contender, false), -1);
    CHECK_EQ_INT(accounts_add_commit(&contender), -1);
    CHECK_EQ_INT(accounts_add_abort(&contender), -1);
    CHECK_EQ_INT(accounts_edit_commit(&contender), -1);
    CHECK_EQ_INT(accounts_edit_abort(&contender), -1);
    CHECK_EQ_INT(accounts_remove_commit(&contender), -1);
    CHECK_EQ_INT(accounts_remove_abort(&contender), -1);
    CHECK_EQ_INT(accounts_transaction_begin(
                     NULL, ACCOUNTS_TRANSACTION_NONE, &rejected), -1);
    CHECK(rejected == UINT64_C(0x5A5A5A5A5A5A5A5A));

    CHECK(memcmp(&owner, &owner_before, sizeof(owner)) == 0);
    CHECK(memcmp(&contender, &contender_before, sizeof(contender)) == 0);
    CHECK_EQ_INT(accounts_transaction_finish(
                     &owner, ACCOUNTS_TRANSACTION_RESET, token), 0);
}

TEST(accounts_init_preserves_guard_and_rollback_obligations) {
    gitswitch_ctx_t ctx;
    gitswitch_ctx_t before;
    config_t config_before;
    size_t skipped_before;
    size_t sections_before;
    size_t keys_before;
    unsigned char zero_accounts[sizeof(ctx.accounts)] = {0};
    const uint64_t checked_token = UINT64_C(0x1122334455667788);

    memset(&ctx, 0x5A, sizeof(ctx));
    before = ctx;
    CHECK_EQ_INT(signals_guard_begin(), 0);
    CHECK(signals_guard_active());
    CHECK_EQ_INT(accounts_init(&ctx), -1);
    CHECK(memcmp(&ctx, &before, sizeof(ctx)) == 0);
    CHECK(signals_guard_active());
    CHECK_EQ_INT(signals_guard_end(), 0);
    CHECK(!signals_guard_active());

    signals_rollback_begin();
    CHECK(signals_rollback_active());
    CHECK_EQ_INT(accounts_init(&ctx), -1);
    CHECK(memcmp(&ctx, &before, sizeof(ctx)) == 0);
    CHECK(signals_rollback_active());
    signals_rollback_end();
    CHECK(!signals_rollback_active());

    CHECK_EQ_INT(signals_rollback_begin_owned(checked_token), 0);
    CHECK_EQ_INT(accounts_init(&ctx), -1);
    CHECK(memcmp(&ctx, &before, sizeof(ctx)) == 0);
    CHECK_EQ_INT(signals_rollback_end_owned(checked_token + 1U), -1);
    CHECK(signals_rollback_active());
    CHECK_EQ_INT(signals_rollback_end_owned(checked_token), 0);
    CHECK(!signals_rollback_active());

    config_before = ctx.config;
    skipped_before = ctx.accounts_skipped_on_load;
    sections_before = ctx.unknown_sections_on_load;
    keys_before = ctx.unknown_keys_on_load;
    CHECK_EQ_INT(accounts_init(&ctx), 0);
    CHECK(memcmp(&ctx.config, &config_before, sizeof(ctx.config)) == 0);
    CHECK(memcmp(ctx.accounts, zero_accounts, sizeof(ctx.accounts)) == 0);
    CHECK_EQ_INT(ctx.account_count, 0);
    CHECK(ctx.current_account == NULL);
    CHECK(ctx.accounts_skipped_on_load == skipped_before);
    CHECK(ctx.unknown_sections_on_load == sections_before);
    CHECK(ctx.unknown_keys_on_load == keys_before);
}

TEST(add_prepare_settles_only_through_exact_commit_or_abort) {
    gitswitch_ctx_t committed;
    gitswitch_ctx_t aborted;
    gitswitch_ctx_t aborted_before;
    gitswitch_ctx_t wrong;
    accounts_transaction_token_t probe = 0;

    make_base_context(&committed);
    make_base_context(&wrong);
    CHECK_EQ_INT(prepare_add_silently(&committed, "committed",
                                      "committed@example.test"), 0);
    CHECK(!accounts_transaction_context_release_safe(&committed));
    CHECK_EQ_INT(committed.account_count, 2);
    CHECK_EQ_INT(accounts_add_commit(&wrong), -1);
    CHECK_EQ_INT(accounts_add_abort(&wrong), -1);
    CHECK_EQ_INT(accounts_init(&wrong), -1);
    CHECK_EQ_INT(accounts_add_commit(&committed), 0);
    CHECK(accounts_transaction_context_release_safe(&committed));
    CHECK_EQ_INT(committed.account_count, 2);
    CHECK_STR_EQ(committed.accounts[1].name, "committed");
    CHECK_EQ_INT(accounts_transaction_begin(
                     &wrong, ACCOUNTS_TRANSACTION_INITIALIZE, &probe), 0);
    if (probe != 0) {
        CHECK_EQ_INT(accounts_transaction_finish(
                         &wrong, ACCOUNTS_TRANSACTION_INITIALIZE, probe), 0);
    }

    make_base_context(&aborted);
    aborted_before = aborted;
    CHECK_EQ_INT(prepare_add_silently(&aborted, "aborted",
                                      "aborted@example.test"), 0);
    CHECK(!accounts_transaction_context_release_safe(&aborted));
    CHECK_EQ_INT(aborted.account_count, 2);
    CHECK_EQ_INT(accounts_add_abort(&wrong), -1);
    CHECK_EQ_INT(accounts_add_abort(&aborted), 0);
    CHECK(accounts_transaction_context_release_safe(&aborted));
    CHECK(memcmp(&aborted, &aborted_before, sizeof(aborted)) == 0);
}

TEST(abort_only_add_owner_blocks_init_and_commit_until_abort_retry) {
    gitswitch_ctx_t owner;
    gitswitch_ctx_t owner_before;
    gitswitch_ctx_t prepared;
    gitswitch_ctx_t contender;
    gitswitch_ctx_t contender_before;
    gitswitch_ctx_t failed_abort_state;
    accounts_transaction_token_t rejected = UINT64_C(0xDEADBEEF);

    make_base_context(&owner);
    make_base_context(&contender);
    owner_before = owner;
    contender_before = contender;
    CHECK_EQ_INT(prepare_add_silently(&owner, "retryable",
                                      "retryable@example.test"), 0);
    prepared = owner;
    CHECK_EQ_INT(owner.account_count, 2);

    /* Manufacture a deterministic model conflict at the abort boundary. The
     * failed abort must retain an abort-only owner; commit is no longer a
     * legal escape hatch, while restoring the model permits exact retry. */
    owner.account_count = 0;
    CHECK_EQ_INT(accounts_add_abort(&owner), -1);
    failed_abort_state = owner;
    CHECK_EQ_INT(accounts_add_commit(&owner), -1);
    CHECK(memcmp(&owner, &failed_abort_state, sizeof(owner)) == 0);
    CHECK_EQ_INT(accounts_init(&contender), -1);
    CHECK_EQ_INT(accounts_session_cleanup(), -1);
    CHECK_EQ_INT(accounts_transaction_begin(
                     &contender, ACCOUNTS_TRANSACTION_SWITCH, &rejected), -1);
    CHECK(rejected == UINT64_C(0xDEADBEEF));
    CHECK(memcmp(&contender, &contender_before, sizeof(contender)) == 0);

    owner = prepared;
    CHECK_EQ_INT(accounts_add_abort(&owner), 0);
    CHECK(memcmp(&owner, &owner_before, sizeof(owner)) == 0);
    CHECK_EQ_INT(accounts_init(&contender), 0);
}

TEST(prepared_edit_retains_guard_rollback_and_exact_abort_owner) {
    gitswitch_ctx_t owner;
    gitswitch_ctx_t owner_before;
    gitswitch_ctx_t contender;
    gitswitch_ctx_t contender_before;
    account_t candidate;

    make_base_context(&owner);
    make_base_context(&contender);
    owner_before = owner;
    contender_before = contender;
    candidate = owner.accounts[0];
    CHECK_EQ_INT(safe_strncpy(candidate.description, "prepared description",
                              sizeof(candidate.description)), 0);

    CHECK_EQ_INT(accounts_edit_candidate_prepare(&owner, &candidate), 0);
    CHECK(!accounts_transaction_context_release_safe(&owner));
    CHECK(accounts_transaction_context_release_safe(&contender));
    CHECK(signals_guard_active());
    CHECK(signals_rollback_active());
    CHECK_STR_EQ(owner.accounts[0].description, "prepared description");
    CHECK_EQ_INT(accounts_edit_abort(&contender), -1);
    CHECK_EQ_INT(accounts_edit_commit(&contender), -1);
    CHECK_EQ_INT(accounts_init(&contender), -1);
    CHECK_EQ_INT(accounts_session_cleanup(), -1);
    CHECK(memcmp(&contender, &contender_before, sizeof(contender)) == 0);
    CHECK(signals_guard_active());
    CHECK(signals_rollback_active());

    CHECK_EQ_INT(accounts_edit_abort(&owner), 0);
    CHECK(accounts_transaction_context_release_safe(&owner));
    CHECK(memcmp(&owner, &owner_before, sizeof(owner)) == 0);
    CHECK(!signals_guard_active());
    CHECK(!signals_rollback_active());
}

TEST(model_mutation_requires_idle_public_state_or_exact_owner_capability) {
    const accounts_transaction_kind_t mutation_kinds[] = {
        ACCOUNTS_TRANSACTION_ADD,
        ACCOUNTS_TRANSACTION_EDIT,
        ACCOUNTS_TRANSACTION_REMOVE,
    };

    for (size_t index = 0;
         index < sizeof(mutation_kinds) / sizeof(mutation_kinds[0]); index++) {
        gitswitch_ctx_t owner;
        gitswitch_ctx_t contender;
        gitswitch_ctx_t owner_before;
        gitswitch_ctx_t contender_before;
        account_t added = make_model_candidate(12, "newmodel", "new model");
        account_t edited;
        accounts_transaction_kind_t kind = mutation_kinds[index];
        accounts_transaction_token_t token = 0;
        accounts_transaction_token_t foreign;

        make_base_context(&owner);
        make_base_context(&contender);
        edited = owner.accounts[0];
        CHECK_EQ_INT(safe_strncpy(edited.description, "edited model",
                                  sizeof(edited.description)), 0);
        owner_before = owner;
        contender_before = contender;
        CHECK_EQ_INT(accounts_transaction_begin(&owner, kind, &token), 0);
        if (token == 0) return;
        foreign = token ^ UINT64_C(0x4000000000000000);
        if (foreign == 0 || foreign == token) foreign = token + 1U;

        /* Public mutation loses to the live owner before argument validation,
         * regardless of whether it targets the owner, another context, or a
         * malformed request. */
        CHECK_EQ_INT(config_add_account(&owner, &added), -1);
        CHECK_EQ_INT(config_remove_account(&owner, 11), -1);
        CHECK_EQ_INT(config_update_account(&owner, &edited), -1);
        CHECK_EQ_INT(config_add_account(&contender, &added), -1);
        CHECK_EQ_INT(config_remove_account(&contender, 11), -1);
        CHECK_EQ_INT(config_update_account(&contender, &edited), -1);
        CHECK_EQ_INT(config_add_account(NULL, NULL), -1);
        CHECK_EQ_INT(config_remove_account(NULL, 0), -1);
        CHECK_EQ_INT(config_update_account(NULL, NULL), -1);

        /* Owned variants accept neither a copied context, a guessed token,
         * nor a capability for another mutation family. */
        CHECK_EQ_INT(config_add_account_owned(&contender, &added, token), -1);
        CHECK_EQ_INT(config_update_account_owned(&contender, &edited, token),
                     -1);
        CHECK_EQ_INT(config_remove_account_owned(&contender, 11, token), -1);
        CHECK_EQ_INT(config_add_account_owned(&owner, &added, foreign), -1);
        CHECK_EQ_INT(config_update_account_owned(&owner, &edited, foreign),
                     -1);
        CHECK_EQ_INT(config_remove_account_owned(&owner, 11, foreign), -1);
        CHECK_EQ_INT(accounts_transaction_authorize_model_mutation(
                         &owner, ACCOUNTS_TRANSACTION_NONE, 0), -1);
        CHECK_EQ_INT(accounts_transaction_authorize_model_mutation(
                         &owner, kind, foreign), -1);

        if (kind != ACCOUNTS_TRANSACTION_ADD) {
            CHECK_EQ_INT(config_add_account_owned(&owner, &added, token), -1);
        }
        if (kind != ACCOUNTS_TRANSACTION_EDIT) {
            CHECK_EQ_INT(config_update_account_owned(&owner, &edited, token),
                         -1);
        }
        if (kind != ACCOUNTS_TRANSACTION_REMOVE) {
            CHECK_EQ_INT(config_remove_account_owned(&owner, 11, token), -1);
        }
        CHECK(memcmp(&owner, &owner_before, sizeof(owner)) == 0);
        CHECK(memcmp(&contender, &contender_before, sizeof(contender)) == 0);

        CHECK_EQ_INT(accounts_transaction_authorize_model_mutation(
                         &owner, kind, token), 0);
        if (kind == ACCOUNTS_TRANSACTION_ADD) {
            CHECK_EQ_INT(config_add_account_owned(&owner, &added, token), 0);
            CHECK_EQ_INT(owner.account_count, 2);
            CHECK_STR_EQ(owner.accounts[1].name, "newmodel");
        } else if (kind == ACCOUNTS_TRANSACTION_EDIT) {
            CHECK_EQ_INT(config_update_account_owned(&owner, &edited, token),
                         0);
            CHECK_STR_EQ(owner.accounts[0].description, "edited model");
        } else {
            CHECK_EQ_INT(config_remove_account_owned(&owner, 11, token), 0);
            CHECK_EQ_INT(owner.account_count, 0);
            CHECK(owner.current_account == NULL);
        }
        CHECK_EQ_INT(accounts_transaction_finish(&owner, kind, token), 0);
    }

    /* Once the exact owner is consumed, ordinary model APIs are admitted. */
    {
        gitswitch_ctx_t ctx;
        account_t added = make_model_candidate(12, "idlemodel", "idle model");

        make_base_context(&ctx);
        CHECK_EQ_INT(config_add_account(&ctx, &added), 0);
        CHECK_EQ_INT(config_remove_account(&ctx, 12), 0);
    }
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(every_kind_pair_requires_exact_context_token_and_depth);
    RUN_TEST(public_cross_type_entrypoints_and_finalizers_preserve_owner);
    RUN_TEST(accounts_init_preserves_guard_and_rollback_obligations);
    RUN_TEST(add_prepare_settles_only_through_exact_commit_or_abort);
    RUN_TEST(abort_only_add_owner_blocks_init_and_commit_until_abort_retry);
    RUN_TEST(prepared_edit_retains_guard_rollback_and_exact_abort_owner);
    RUN_TEST(model_mutation_requires_idle_public_state_or_exact_owner_capability);
TEST_MAIN_END()
