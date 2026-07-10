/* gitswitch-c: Main header with common definitions and constants */

#ifndef GITSWITCH_H
#define GITSWITCH_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* Version information. The real version is injected via -DGITSWITCH_VERSION
 * from the VERSION file by the Makefile; this sentinel only appears when a
 * source file is compiled outside the build system (never on a release). */
#ifndef GITSWITCH_VERSION
#define GITSWITCH_VERSION "0.0.0-dev"
#endif
#ifndef GITSWITCH_COMMIT
#define GITSWITCH_COMMIT "unknown"
#endif
#define GITSWITCH_NAME "gitswitch-c"

/* Configuration constants */
#define MAX_PATH_LEN 4096
#define MAX_NAME_LEN 256
#define MAX_EMAIL_LEN 320  /* RFC 5321 limit */
#define MAX_DESC_LEN 512
#define MAX_KEY_ID_LEN 64
#define MAX_ACCOUNTS 64

/* Default configuration paths */
#define DEFAULT_CONFIG_DIR ".config/gitswitch"
#define DEFAULT_CONFIG_FILE "accounts.toml"
#define DEFAULT_SSH_DIR ".ssh"
#define DEFAULT_GPG_DIR ".gnupg"

/* Exit codes */
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define EXIT_CONFIG_ERROR 2
#define EXIT_VALIDATION_ERROR 3
#define EXIT_SSH_ERROR 4
#define EXIT_GPG_ERROR 5

/* Git scopes */
typedef enum {
    GIT_SCOPE_LOCAL,
    GIT_SCOPE_GLOBAL,
    GIT_SCOPE_SYSTEM
} git_scope_t;

/* Account structure */
typedef struct {
    uint32_t id;
    char name[MAX_NAME_LEN];
    char email[MAX_EMAIL_LEN];
    char description[MAX_DESC_LEN];
    git_scope_t preferred_scope;
    
    /* SSH configuration */
    bool ssh_enabled;
    char ssh_key_path[MAX_PATH_LEN];
    char ssh_host_alias[MAX_NAME_LEN];
    
    /* GPG configuration */
    bool gpg_enabled;
    bool gpg_signing_enabled;
    char gpg_key_id[MAX_KEY_ID_LEN];
    
} account_t;

/* Global configuration */
typedef struct {
    git_scope_t default_scope;
    char config_path[MAX_PATH_LEN];
    char active_account[MAX_NAME_LEN];  /* Last-switched account, persisted for boot resume */
    bool verbose;
    bool dry_run;
    bool color_output;
    bool force_global;   /* --global: write global scope (and consent to it outside a repo) */
    bool force_local;    /* --local:  force local scope */
    bool resuming;       /* set during boot-time `resume`: skip the blocking,
                          * purely-informational SSH connection test so the
                          * login shell prompt isn't stalled on a network RTT */
    bool assume_yes;     /* --yes: skip interactive confirmation prompts */
} config_t;

/* Application context */
typedef struct {
    config_t config;
    account_t accounts[MAX_ACCOUNTS];
    size_t account_count;
    account_t *current_account;
    /* Number of account sections present in the config file that were dropped
     * at load time because they failed validation (e.g. an SSH key on an
     * unmounted path, or wrong permissions). When non-zero the in-memory set
     * is an incomplete view of the file, so config_save must NOT rewrite the
     * file — doing so would silently erase the dropped accounts. */
    size_t accounts_skipped_on_load;
} gitswitch_ctx_t;

/* Function prototypes */
int gitswitch_init(gitswitch_ctx_t *ctx);
void gitswitch_cleanup(gitswitch_ctx_t *ctx);

#endif /* GITSWITCH_H */