/* Tests for gpg_switch_account's spawn economy (AR-02 #14): a repeat switch
 * to an account whose key already sits in the isolated home used to spawn gpg
 * separately for the import idempotency check AND the signing-capability
 * test, answering the same "is the secret key here?" question twice. The
 * idempotency probe now asks with --with-colons and its listing doubles as
 * the signing evidence, so the whole ISOLATED switch takes ONE gpg spawn.
 *
 * gpg invocations are intercepted with a counting fake runner; the isolated
 * home lives under a private fake XDG_RUNTIME_DIR, with the tmpfs fail-closed
 * guard opted out via GITSWITCH_ALLOW_TMP_GPG so the test is independent of
 * where the suite's scratch space happens to be mounted. */

/* glibc-only: on macOS and the BSDs the strict macros hide default-namespace
 * declarations (mkdtemp) — the trap documented in ssh_manager.c. */
#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#endif

#include "test.h"
#include "gitswitch.h"
#include "gpg_manager.h"
#include "utils.h"
#include "error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* A real `sec` line whose capability field (12) contains 's'. */
#define SEC_SIGN "sec:-:4096:1:FEEDFACE01234567:1700000000:::-:::scESC:::+:::23::0:\n"

static int g_gpg_execs;

/* Counts gpg spawns; answers any secret-key listing with a signing-capable
 * record, so the switch's already-present fast path is taken. */
static int counting_runner(const char *const argv[], const run_opts_t *opts,
                           run_result_t *result) {
    if (result) {
        memset(result, 0, sizeof(*result));
        result->spawned = true;
    }
    if (opts && opts->out && opts->out_size > 0) opts->out[0] = '\0';

    if (strcmp(argv[0], "gpg") == 0) {
        g_gpg_execs++;
        bool listing = false;
        for (int i = 1; argv[i]; i++) {
            if (strcmp(argv[i], "--list-secret-keys") == 0) listing = true;
        }
        if (listing && opts && opts->out) {
            snprintf(opts->out, opts->out_size, "%s", SEC_SIGN);
            if (result) result->out_len = strlen(opts->out);
        }
    }
    return 0;
}

TEST(repeat_isolated_switch_spawns_gpg_once) {
    char xdg[128], link_path[512], target[512];
    gpg_config_t cfg;
    account_t acct;
    command_runner_fn prev;
    ssize_t n;
    int rc;

    snprintf(xdg, sizeof(xdg), "/tmp/gswgpgsw_XXXXXX");
    CHECK(mkdtemp(xdg) != NULL);
    CHECK_EQ_INT(chmod(xdg, 0700), 0);
    setenv("XDG_RUNTIME_DIR", xdg, 1);
    setenv("GITSWITCH_ALLOW_TMP_GPG", "1", 1);

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = GPG_MODE_ISOLATED;
    memset(&acct, 0, sizeof(acct));
    snprintf(acct.name, sizeof(acct.name), "work");
    snprintf(acct.email, sizeof(acct.email), "w@x.com");
    acct.gpg_enabled = true;
    acct.gpg_signing_enabled = true;
    snprintf(acct.gpg_key_id, sizeof(acct.gpg_key_id), "FEEDFACE01234567");

    g_gpg_execs = 0;
    prev = run_set_runner(counting_runner);
    rc = gpg_switch_account(&cfg, &acct);
    run_set_runner(prev);

    CHECK_EQ_INT(rc, 0);
    /* One spawn proves presence AND signing capability (pre-fix: two — the
     * plain idempotency listing plus gpg_test_signing's --with-colons rerun). */
    CHECK_EQ_INT(g_gpg_execs, 1);

    /* The stable `current` symlink was retargeted at this account's home. */
    CHECK_EQ_INT(gpg_manager_get_home_path(link_path, sizeof(link_path)), 0);
    n = readlink(link_path, target, sizeof(target) - 1);
    CHECK(n > 0);
    if (n > 0) {
        target[n] = '\0';
        CHECK(strstr(target, "/work") != NULL);
    }

    unsetenv("GITSWITCH_ALLOW_TMP_GPG");
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_ERROR, NULL);
    RUN_TEST(repeat_isolated_switch_spawns_gpg_once);
TEST_MAIN_END()
