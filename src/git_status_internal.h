#ifndef GIT_STATUS_INTERNAL_H
#define GIT_STATUS_INTERNAL_H

#include "git_ops.h"

/* Internal, heap-owned projection of one atomic effective Git listing. Keep
 * this out of git_current_config_t: that retained API writes into caller-owned
 * storage and its layout must remain stable. */
typedef struct {
    git_config_effective_value_t user_name;
    git_config_effective_value_t user_email;
    git_config_effective_value_t user_signing_key;
    git_config_effective_value_t commit_gpgsign;
    git_config_effective_value_t gpg_format;
    git_config_effective_value_t ssh_command;
    git_config_effective_value_t gpg_program;
    git_config_effective_value_t gpg_openpgp_program;
    git_config_effective_value_t gpg_x509_program;
    git_config_effective_value_t gpg_ssh_program;
    bool gpg_signing_enabled;
    bool commit_gpgsign_invalid;
    bool gpg_format_invalid;
    bool any_present;
    bool valid;
} git_status_snapshot_t;

#ifdef GITSWITCH_INTERNAL_API
/* On a semantically invalid leg, read returns -1 but may still publish a
 * heap snapshot from the complete atomic listing so status can render the
 * other authoritative legs. Transport/framing/allocation failures publish
 * no snapshot. Every non-NULL result must be freed. */
int git_status_snapshot_read(git_status_snapshot_t **snapshot);
void git_status_snapshot_free(git_status_snapshot_t *snapshot);
int git_status_snapshot_to_current(const git_status_snapshot_t *snapshot,
                                   git_current_config_t *current);
#endif

#endif
