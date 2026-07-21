/* FreeBSD build contract shared by the application and release publisher.
 *
 * FreeBSD 14.4 is the oldest upstream-supported release in the AR-11 M23
 * support window and is the exact release exercised by the hosted full-suite
 * gate.  The descriptor-conditioned publication paths require O_PATH and
 * funlinkat(2); older release headers must receive one intentional diagnostic
 * instead of failing later at scattered API uses. */

#ifndef GITSWITCH_FREEBSD_COMPAT_H
#define GITSWITCH_FREEBSD_COMPAT_H

#define GITSWITCH_FREEBSD_MIN_VERSION 1404000
#define GITSWITCH_FREEBSD_MIN_RELEASE "14.4"

#if defined(__FreeBSD__)
#include <sys/param.h>

#if !defined(__FreeBSD_version)
#error "gitswitch requires <sys/param.h> to define __FreeBSD_version"
#elif __FreeBSD_version < GITSWITCH_FREEBSD_MIN_VERSION
#error "gitswitch requires FreeBSD 14.4 or newer (__FreeBSD_version >= 1404000)"
#else
#include <fcntl.h>
#if !defined(O_PATH)
#error "gitswitch requires FreeBSD headers exposing O_PATH"
#endif
#endif
#endif

#endif
