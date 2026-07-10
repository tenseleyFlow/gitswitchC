/* AR-05 adversarial unit tests — fresh-eyes coverage of validator/injection
 * behaviors that the existing suites (test_validation.c, test_security.c,
 * test_toml.c) leave untested, plus neuter-checks for AR-04 fixes that would
 * still pass every current test if the fix were quietly reverted.
 *
 * These are pure-function tests on utils.c gates that sit directly in front of
 * security-sensitive sinks:
 *   - validate_name   -> path component (<base>/<name>, ssh-agent.<name>.sock)
 *                        and git user.name; also the M3 socket-name parser.
 *   - validate_email  -> written verbatim as user.email into ~/.gitconfig.
 *   - validate_key_id -> handed to gpg/git as an argv element.
 *   - is_safe_ssh_key_path -> core.sshCommand (/bin/sh) and ~/.ssh/config.
 *
 * Each assertion documents the *expected safe* behavior. A failing assertion is
 * a real defect in the current tree, not a broken test — see result_summary.
 */
#include "test.h"
#include "gitswitch.h"
#include "utils.h"
#include "error.h"
#include <string.h>

/* ------------------------------------------------------------------------- *
 * M3 non-regression: names containing ".sock" must stay valid.
 *
 * AR-04 M3 fixed the current-account detector to parse the socket basename by
 * its terminal ".sock" suffix instead of the first strstr(".sock"), and the
 * ticket explicitly forbids "fixing" it by banning ".sock" inside account
 * names. test_validation.c never exercises a ".sock" name, so a regression that
 * re-hardened validate_name to reject ".sock" (re-introducing the truncation
 * bug via the back door) would pass the entire existing suite. This locks it. */
TEST(validate_name_allows_embedded_sock_tokens) {
    CHECK(validate_name("alice.sock.work"));   /* the exact M3 repro name */
    CHECK(validate_name("x.sock"));            /* trailing .sock */
    CHECK(validate_name(".sock") == false);    /* leading dot still refused */
    CHECK(validate_name("a.sock.b.sock.c"));   /* multiple .sock substrings */
    CHECK(validate_name("current.sock"));      /* NOT the reserved "current" */
    CHECK(validate_name("sock"));
    CHECK(validate_name("work.socket"));
}

/* ------------------------------------------------------------------------- *
 * validate_name: separator/traversal cases the existing suite skips.
 * test_validation.c covers "a/b", "a\\b", "..", "a..b", "../evil". It does NOT
 * cover a trailing separator, a lone ".." split across the string edge, an
 * embedded NUL-adjacent form, or a name that is a bare "-"/"--". These all reach
 * the filesystem/argv as a path component or option. */
TEST(validate_name_rejects_edge_separators_and_options) {
    CHECK(!validate_name("work/"));            /* trailing slash */
    CHECK(!validate_name("/work"));            /* leading slash */
    CHECK(!validate_name("work\\"));           /* trailing backslash */
    CHECK(!validate_name("a/../b"));           /* traversal mid-string */
    CHECK(!validate_name("-"));                /* bare option-dash */
    CHECK(!validate_name("--"));               /* also ".." via strstr? no: option */
    CHECK(!validate_name("..work"));           /* leading ".." */
    CHECK(!validate_name("work.."));           /* trailing ".." */
    CHECK(!validate_name("\t"));               /* lone tab (control) */
    CHECK(!validate_name("\x1b"));             /* lone ESC */
}

/* ------------------------------------------------------------------------- *
 * validate_email injection guard: an email is written verbatim into
 * ~/.gitconfig as `email = <value>`. A trailing or embedded newline/CR would
 * split that line and inject an arbitrary git config directive; a NUL/control
 * byte is equally illegal. validate_email is the ONLY gate. test_validation.c
 * only checks length bounds and "not-an-email"/""/NULL — never a control byte.
 * This is the highest-value untested case in the file. */
TEST(validate_email_rejects_embedded_control_and_newline) {
    CHECK(!validate_email("user@example.com\n"));            /* trailing LF */
    CHECK(!validate_email("user@example.com\r"));            /* trailing CR */
    CHECK(!validate_email("user@example.com\n[core]\nx=y")); /* full injection */
    CHECK(!validate_email("us\ner@example.com"));            /* interior LF */
    CHECK(!validate_email("user@ex\tample.com"));            /* interior TAB */
    CHECK(!validate_email("user@example.com "));             /* trailing space */
    CHECK(!validate_email(" user@example.com"));             /* leading space */

    /* Positive controls so the test cannot pass by rejecting everything. */
    CHECK(validate_email("user@example.com"));
    CHECK(validate_email("j.doe+tag@sub.example.co"));
}

/* ------------------------------------------------------------------------- *
 * is_safe_ssh_key_path: NOT referenced by any test file in the tree, yet it is
 * the shared guard for the two SSH-key sinks (core.sshCommand handed to /bin/sh
 * with the path in single quotes, and the IdentityFile line in ~/.ssh/config).
 * A single quote ends the shell quote and smuggles ssh options
 * (-oProxyCommand=...); a newline injects an ssh_config keyword. */
TEST(is_safe_ssh_key_path_blocks_quote_and_control_injection) {
    /* Single quote: breaks out of the '...' wrapper in core.sshCommand. */
    CHECK(!is_safe_ssh_key_path("/home/u/.ssh/id' -oProxyCommand=calc '"));
    CHECK(!is_safe_ssh_key_path("/home/u/id_ed25519'"));
    /* Double quote: breaks ~/.ssh/config directive tokenization. */
    CHECK(!is_safe_ssh_key_path("/home/u/\"evil\"/key"));
    /* Newline / CR: inject a new ssh_config line (ProxyCommand). */
    CHECK(!is_safe_ssh_key_path("/home/u/key\nProxyCommand id"));
    CHECK(!is_safe_ssh_key_path("/home/u/key\rProxyCommand id"));
    /* Other control bytes and DEL. */
    CHECK(!is_safe_ssh_key_path("/home/u/key\tfoo"));
    CHECK(!is_safe_ssh_key_path("/home/u/key\x7f"));
    CHECK(!is_safe_ssh_key_path("\x01/home/u/key"));

    /* Legitimate key paths (including a space, which is fine) must pass. */
    CHECK(is_safe_ssh_key_path("/home/u/.ssh/id_ed25519"));
    CHECK(is_safe_ssh_key_path("/home/Jane Doe/.ssh/id_rsa"));
    CHECK(is_safe_ssh_key_path("~/.ssh/id_ed25519"));
}

/* ------------------------------------------------------------------------- *
 * validate_key_id: exact-boundary acceptance and control/space rejection that
 * test_validation.c does not pin. The id reaches gpg/git argv, so an interior
 * space or NL that survived would split into extra arguments if a caller ever
 * mishandled it; the validator must forbid them regardless. */
TEST(validate_key_id_boundary_and_control) {
    /* Longest storable id (MAX_KEY_ID_LEN-1 hex chars) is accepted. */
    char maxhex[MAX_KEY_ID_LEN];
    memset(maxhex, 'A', MAX_KEY_ID_LEN - 1);
    maxhex[MAX_KEY_ID_LEN - 1] = '\0';
    CHECK(validate_key_id(maxhex));

    /* One over the storable bound is refused. */
    char over[MAX_KEY_ID_LEN + 1];
    memset(over, 'A', MAX_KEY_ID_LEN);
    over[MAX_KEY_ID_LEN] = '\0';
    CHECK(!validate_key_id(over));

    /* 0x + single hex digit is the minimal accepted prefixed id. */
    CHECK(validate_key_id("0xA"));
    CHECK(validate_key_id("0"));            /* single hex digit */

    /* Control bytes / whitespace never belong in a key id. */
    CHECK(!validate_key_id("DEADBEEF\n"));
    CHECK(!validate_key_id("DEAD\tBEEF"));
    CHECK(!validate_key_id("DEAD BEEF"));
    CHECK(!validate_key_id("0x DEADBEEF"));
    CHECK(!validate_key_id("0x\tAB"));
}

/* ------------------------------------------------------------------------- *
 * Reserved-name completeness: the reservation is case-insensitive and EXACT.
 * Guard both that "current" variants stay refused and that decorated forms
 * (which do not collide with the <base>/current stable link) stay usable, so a
 * future over-broad "contains current" check cannot slip in unnoticed. */
TEST(validate_name_reserved_current_is_exact_and_ci) {
    CHECK(!validate_name("current"));
    CHECK(!validate_name("CURRENT"));
    CHECK(!validate_name("CuRrEnT"));
    /* Decorated / adjacent forms remain valid path components. */
    CHECK(validate_name("current-work"));
    CHECK(validate_name("work-current"));
    CHECK(validate_name("currentish"));
    CHECK(validate_name("my current"));   /* space-separated, distinct dir */
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(validate_name_allows_embedded_sock_tokens);
    RUN_TEST(validate_name_rejects_edge_separators_and_options);
    RUN_TEST(validate_email_rejects_embedded_control_and_newline);
    RUN_TEST(is_safe_ssh_key_path_blocks_quote_and_control_injection);
    RUN_TEST(validate_key_id_boundary_and_control);
    RUN_TEST(validate_name_reserved_current_is_exact_and_ci);
TEST_MAIN_END()
