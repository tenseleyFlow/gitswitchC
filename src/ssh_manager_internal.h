#ifndef SSH_MANAGER_INTERNAL_H
#define SSH_MANAGER_INTERNAL_H

#include "ssh_manager.h"
#include "config.h"

#ifdef GITSWITCH_INTERNAL_API
typedef struct ssh_key_admission ssh_key_admission_t;

/* Capture and later consume one remove-only alias obligation against the exact
 * canonical HOME and optional safe ~/.ssh directory generation. Capture and
 * revalidation are read-only. Removal refuses a changed namespace before
 * reading or publishing config bytes. */
int ssh_capture_host_alias_obligation(
    const char *alias,
    config_retirement_ssh_alias_obligation_t *obligation);
int ssh_remove_host_alias_obligation_result(
    const config_retirement_ssh_alias_obligation_t *obligation,
    ssh_config_publication_state_t *publication);
int ssh_revalidate_host_alias_obligation(
    const config_retirement_ssh_alias_obligation_t *obligation);

/* Read and structurally validate the current ~/.ssh/config snapshot before an
 * account switch can mutate runtime or Git state. This creates no directory,
 * lock, temporary, or generation reservation; the final publisher must still
 * lock, reread, parse, and revalidate its own current snapshot. */
int ssh_preflight_host_alias_config(const account_t *account);

/* Capture and OpenSSH-parse one exact private-key generation, retain its
 * descriptor-backed bytes across account-layer preflight, and bind activation
 * to those bytes. `verify_named` is the final no-mutation checkpoint: it
 * proves the configured pathname still names the admitted generation, then
 * detaches the immutable in-memory generation from the mutable source inode.
 * The admitted switch borrows the handle; the caller always ends it. */
int ssh_key_admission_begin(const char *expanded_key_path,
                            ssh_key_admission_t **admission);
int ssh_key_admission_verify_named(ssh_key_admission_t *admission);
int ssh_switch_account_admitted(ssh_config_t *ssh_config,
                                const account_t *account,
                                ssh_key_admission_t *admission);
void ssh_key_admission_end(ssh_key_admission_t **admission);

/* Exercise the portable fixed-slot recovery contract on every development
 * platform without adding recovery mechanics to the supported public API. */
int ssh_manager_test_fingerprint_slot_name(int dir_fd, char *name,
                                           size_t name_size);
int ssh_manager_test_recover_fingerprint_slot(int dir_fd);
#endif

#endif
