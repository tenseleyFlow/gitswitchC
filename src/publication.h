/* Durable Git-publication provenance shared by AR-11 M8-M10. */

#ifndef PUBLICATION_H
#define PUBLICATION_H

#include "gitswitch.h"

#include <inttypes.h>
#include <sys/stat.h>

#define PUBLICATION_LEDGER_VERSION 1U
#define PUBLICATION_LEDGER_MAX_RECORDS 128U
#define PUBLICATION_LEDGER_MAX_BYTES (8U * 1024U * 1024U)
#define PUBLICATION_SSH_COMMAND_MAX \
    (MAX_PATH_LEN * 5U + MAX_NAME_LEN + 256U)

#define PUBLICATION_CAP_DESTINATION     UINT32_C(0x00000001)
#define PUBLICATION_CAP_POST_GENERATION UINT32_C(0x00000002)
#define PUBLICATION_CAP_GPG_FINGERPRINT UINT32_C(0x00000004)
#define PUBLICATION_CAP_GPG_PROGRAM     UINT32_C(0x00000008)
#define PUBLICATION_CAP_SSH_COMMAND     UINT32_C(0x00000010)
#define PUBLICATION_CAP_SSH_PROGRAM     UINT32_C(0x00000020)
#define PUBLICATION_CAP_GPG_SELECTOR    UINT32_C(0x00000040)
#define PUBLICATION_CAP_GPG_SIGNING_STATE UINT32_C(0x00000080)
#define PUBLICATION_CAP_ALL               UINT32_C(0x000000ff)

typedef enum {
    PUBLICATION_SCOPE_LOCAL = 0,
    PUBLICATION_SCOPE_GLOBAL,
    PUBLICATION_SCOPE_WORKTREE
} publication_scope_t;

typedef enum {
    PUBLICATION_STATE_PUBLISHED = 0,
    PUBLICATION_STATE_RETIRING
} publication_state_t;

/* A stable object/generation witness serialized without relying on native
 * struct-stat layout. Directories use namespace-stable identity fields;
 * regular post-images additionally use link count, size, mtime, and ctime to
 * distinguish in-place rewrites (including a rewrite that restores mtime). */
typedef struct {
    bool present;
    uintmax_t device;
    uintmax_t inode;
    uintmax_t mode;
    uintmax_t uid;
    uintmax_t gid;
    uintmax_t link_count;
    uintmax_t size;
    int64_t mtime_seconds;
    uint32_t mtime_nanoseconds;
    int64_t ctime_seconds;
    uint32_t ctime_nanoseconds;
} publication_identity_t;

typedef struct {
    uint32_t account_id;
    char account_incarnation[ACCOUNT_INCARNATION_LEN];
    publication_scope_t scope;
    char config_path[MAX_PATH_LEN];
    publication_identity_t config_parent;
    char repository_path[MAX_PATH_LEN];
    publication_identity_t repository;
    publication_identity_t post_config;
    uint32_t capabilities;
    char gpg_fingerprint[MAX_GPG_FINGERPRINT_LEN];
    char gpg_selector[MAX_GPG_SELECTOR_LEN];
    char gpg_program[MAX_PATH_LEN];
    publication_identity_t gpg_program_identity;
    /* Exact commit.gpgsign value sealed with the OpenPGP publication. The
     * capability bit distinguishes a recorded false value from a legacy
     * record that predates this witness. */
    bool gpg_signing_enabled;
    char ssh_command[PUBLICATION_SSH_COMMAND_MAX];
    char ssh_program[MAX_PATH_LEN];
    publication_identity_t ssh_program_identity;
    publication_state_t state;
} publication_record_t;

typedef struct {
    bool present;
    unsigned int version;
    publication_record_t *records;
    size_t count;
} publication_ledger_t;

typedef enum {
    PUBLICATION_LOOKUP_ERROR = -1,
    PUBLICATION_LOOKUP_ABSENT = 0,
    PUBLICATION_LOOKUP_FOUND = 1
} publication_lookup_status_t;

void publication_identity_from_stat(publication_identity_t *identity,
                                    const struct stat *st);
bool publication_identity_equal(const publication_identity_t *left,
                                const publication_identity_t *right);
int publication_normalize_gpg_selector(
    const char *selector, char normalized[MAX_GPG_SELECTOR_LEN]);
/* Extract the absolute executable from the first quoted word of the exact
 * managed core.sshCommand grammar. This performs no filesystem or PATH
 * lookup; callers can use it to bind and validate durable provenance. */
int publication_extract_ssh_program(const char *command, char *out,
                                    size_t out_size);
void publication_record_init(publication_record_t *record);
int publication_record_validate(const publication_record_t *record);
/* Compare the stable configuration namespace independently of repository
 * witnesses. Linked Git worktrees have distinct repository roots while
 * legitimately sharing one local config file. */
bool publication_record_same_config_destination(
    const publication_record_t *left,
    const publication_record_t *right);
/* Verify one record's live config/repository namespace. The config generation
 * may be supplied by any PUBLISHED record for the same account incarnation
 * and stable config destination, which models linked worktrees that share a
 * config file but retain distinct repository witnesses. */
int publication_record_verify_live_destination(
    const publication_record_t *record,
    const publication_record_t *const generation_records[],
    size_t generation_count,
    const publication_record_t **live_generation);
bool publication_record_same_destination(const publication_record_t *left,
                                         const publication_record_t *right);
/* Retained for source compatibility with the v1 publication-ledger API.
 * A live filesystem observation cannot prove that a recorded destination was
 * permanently deleted: ENOENT and changed identity are both reproducible by
 * rename-away/restore.  Consequently v1 records are never automatically
 * classified as absent or reclaimed. */
bool publication_record_destination_provably_absent(
    const publication_record_t *record);
size_t publication_ledger_reclaim_absent(publication_ledger_t *ledger);
bool publication_ledger_destination_present(
    const publication_ledger_t *ledger,
    const publication_record_t *record);

void publication_ledger_init(publication_ledger_t *ledger);
void publication_ledger_clear(publication_ledger_t *ledger);
int publication_ledger_upsert(publication_ledger_t *ledger,
                              const publication_record_t *record);
publication_lookup_status_t publication_ledger_find(
    const publication_ledger_t *ledger, uint32_t account_id,
    const char *account_incarnation,
    publication_scope_t scope, const char *config_path,
    const char *repository_path, const publication_record_t **record);

/* Parse/serialize only the optional tail beginning `publications=v1`. An
 * empty input is the legacy ledger-absent representation. Successful parsing
 * consumes the complete input and accepts only the canonical v1 grammar.
 * Before its first parse, `ledger` must be initialized with
 * publication_ledger_init(); success clears and replaces its prior contents,
 * while failure leaves those initialized contents unchanged. Clear the final
 * model with publication_ledger_clear(). */
int publication_ledger_parse(const unsigned char *data, size_t length,
                             publication_ledger_t *ledger);
int publication_ledger_serialize(const publication_ledger_t *ledger,
                                 unsigned char **data, size_t *length);

#if defined(GITSWITCH_TESTING) && \
    defined(GITSWITCH_PUBLICATION_SERIALIZER_TEST_API)
/* Peak backing allocation used by the most recent serializer call. */
size_t publication_test_last_serializer_peak_capacity(void);
#endif

#endif /* PUBLICATION_H */
