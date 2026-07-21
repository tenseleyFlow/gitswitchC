#ifndef SSH_MANAGER_INTERNAL_H
#define SSH_MANAGER_INTERNAL_H

#include "ssh_manager.h"

#ifdef GITSWITCH_INTERNAL_API
/* Read and structurally validate the current ~/.ssh/config snapshot before an
 * account switch can mutate runtime or Git state. This creates no directory,
 * lock, temporary, or generation reservation; the final publisher must still
 * lock, reread, parse, and revalidate its own current snapshot. */
int ssh_preflight_host_alias_config(const account_t *account);
#endif

#endif
