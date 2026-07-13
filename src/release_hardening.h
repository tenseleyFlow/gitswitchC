#ifndef GITSWITCH_RELEASE_HARDENING_H
#define GITSWITCH_RELEASE_HARDENING_H

/*
 * Forced into every release translation unit by the Makefile. This turns a
 * missing/neutralized stack-protector policy into a per-object compile error,
 * instead of accepting a final binary merely because one unrelated object
 * happened to reference __stack_chk_fail.
 */
#if defined(GITSWITCH_REQUIRE_STRONG_SSP) && \
    !defined(__SSP_STRONG__) && !defined(__SSP_ALL__)
#error "release translation unit lacks required stack-protector policy"
#endif

#endif /* GITSWITCH_RELEASE_HARDENING_H */
