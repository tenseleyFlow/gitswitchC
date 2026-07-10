/* Unit tests for the identifier validators in utils.c.
 *
 * validate_name: the account name doubles as a filesystem path component
 * (isolated GNUPGHOME <base>/<name>, ssh-agent.<name>.sock) and as the git
 * user.name, so it must stay a single safe path component while ordinary
 * display names keep working. These tests lock the traversal/separator/
 * option-injection guards and the reserved-"current" refusal.
 *
 * validate_key_id: the GPG key id is handed to gpg/git as an argument, so it
 * must be hex only (with the cosmetic 0x prefix gpg itself accepts). */
#include "test.h"
#include "gitswitch.h"
#include "utils.h"
#include "error.h"
#include <string.h>

TEST(validate_name_rejects_path_traversal_and_seps) {
    /* Path separators: either one would let the name escape the isolation
     * base directory (or nest under it). */
    CHECK(!validate_name("a/b"));
    CHECK(!validate_name("a\\b"));
    CHECK(!validate_name("/etc"));

    /* Traversal: ".." anywhere, and the leading-dot forms. "reset .." would
     * otherwise resolve <base>/.. and delete the parent tree. */
    CHECK(!validate_name(".."));
    CHECK(!validate_name("a..b"));
    CHECK(!validate_name("../evil"));
    CHECK(!validate_name(".hidden"));
    CHECK(!validate_name("."));

    /* Leading '-': git/ssh could read the name as an option. */
    CHECK(!validate_name("-oProxyCommand=x"));
    CHECK(!validate_name("--global"));
}

TEST(validate_name_rejects_control_chars_and_reserved) {
    /* C0 control characters and DEL: newline splits config/ssh_config lines,
     * ESC drives the terminal. */
    CHECK(!validate_name("a\nb"));
    CHECK(!validate_name("a\rb"));
    CHECK(!validate_name("a\x1b[31mb"));
    CHECK(!validate_name("a\tb"));
    CHECK(!validate_name("a\x7f b"));

    /* Reserved: <base>/current is the stable symlink the shell integration
     * follows; an account named "current" (any case) would squat on it. */
    CHECK(!validate_name("current"));
    CHECK(!validate_name("CURRENT"));
    CHECK(!validate_name("Current"));

    /* Degenerate inputs. */
    CHECK(!validate_name(NULL));
    CHECK(!validate_name(""));
    CHECK(!validate_name("   "));
    char toolong[MAX_NAME_LEN + 2];
    memset(toolong, 'a', sizeof(toolong) - 1);
    toolong[sizeof(toolong) - 1] = '\0';
    CHECK(!validate_name(toolong));
}

TEST(validate_name_accepts_ordinary_display_names) {
    /* Regression guard: the hardening must not reject legitimate names
     * (spaces, parentheses, interior dots/dashes). */
    CHECK(validate_name("Jane Doe (Work)"));
    CHECK(validate_name("work"));
    CHECK(validate_name("work-backup"));
    CHECK(validate_name("j.doe"));
    CHECK(validate_name("currently")); /* only exactly "current" is reserved */
}

TEST(validate_key_id_is_hex_only) {
    /* Plain and 0x-prefixed hex are accepted (gpg prints and accepts both). */
    CHECK(validate_key_id("DEADBEEFCAFE1234"));
    CHECK(validate_key_id("deadbeef"));
    CHECK(validate_key_id("0xDEADBEEFCAFE1234"));
    CHECK(validate_key_id("0Xdeadbeef"));

    /* Non-hex must be refused: these reach gpg/git argv as the key id. */
    CHECK(!validate_key_id("DEADBEEG"));            /* 'G' not hex */
    CHECK(!validate_key_id("DEAD BEEF"));           /* space */
    CHECK(!validate_key_id("$(id)"));               /* shell-ish payload */
    CHECK(!validate_key_id("DEADBEEF;rm -rf ~"));
    CHECK(!validate_key_id("-DEADBEEF"));           /* option-like */
    CHECK(!validate_key_id("0x"));                  /* prefix with no digits */
    CHECK(!validate_key_id("0x0xAB"));              /* only one prefix */
    CHECK(!validate_key_id(""));
    CHECK(!validate_key_id(NULL));

    char toolong[MAX_KEY_ID_LEN + 2];
    memset(toolong, 'A', sizeof(toolong) - 1);
    toolong[sizeof(toolong) - 1] = '\0';
    CHECK(!validate_key_id(toolong));
}

TEST_MAIN_BEGIN()
    error_init(LOG_LEVEL_WARNING, NULL);
    RUN_TEST(validate_name_rejects_path_traversal_and_seps);
    RUN_TEST(validate_name_rejects_control_chars_and_reserved);
    RUN_TEST(validate_name_accepts_ordinary_display_names);
    RUN_TEST(validate_key_id_is_hex_only);
TEST_MAIN_END()
