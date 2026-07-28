#ifndef GITSWITCH_PROCESS_FORK_INTERNAL_H
#define GITSWITCH_PROCESS_FORK_INTERNAL_H

typedef void (*process_fork_child_cleanup_fn)(void);

/* Cleanup callbacks run after the shared descriptor registries are reset in
 * the post-fork child. They must not allocate, log, or acquire locks. */
int process_fork_child_cleanup_register(
    process_fork_child_cleanup_fn cleanup);

#endif
