/*
 * Stub libshare.h for Axiom
 * FreeBSD's libzfs.h includes libshare.h but we don't need sharing functionality
 */

#ifndef _LIBSHARE_H
#define _LIBSHARE_H

#include <sys/types.h>
#include <stdint.h>

/* Solaris-style typedefs used by nvpair.h */
#ifndef _UINT_T
#define _UINT_T
typedef unsigned int uint_t;
#endif

#ifndef _UCHAR_T
#define _UCHAR_T
typedef unsigned char uchar_t;
#endif

#ifndef _USHORT_T
#define _USHORT_T
typedef unsigned short ushort_t;
#endif

#ifndef _ULONG_T
#define _ULONG_T
typedef unsigned long ulong_t;
#endif

#ifndef _BOOLEAN_T
#define _BOOLEAN_T
typedef enum { B_FALSE = 0, B_TRUE = 1 } boolean_t;
#endif

#ifndef _HRTIME_T
#define _HRTIME_T
typedef int64_t hrtime_t;
#endif

/* Minimal stubs to satisfy libzfs.h */

#endif /* _LIBSHARE_H */
