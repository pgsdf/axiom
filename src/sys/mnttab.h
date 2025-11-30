/*
 * Stub sys/mnttab.h for Axiom
 * FreeBSD uses different mount table APIs (getmntinfo, statfs)
 * This stub satisfies libzfs.h which expects Solaris mnttab
 */

#ifndef _SYS_MNTTAB_H
#define _SYS_MNTTAB_H

#include <sys/types.h>

/* Solaris mnttab structure - not actually used on FreeBSD */
struct mnttab {
    char *mnt_special;
    char *mnt_mountp;
    char *mnt_fstype;
    char *mnt_mntopts;
};

#define MNTTAB "/etc/fstab"

#endif /* _SYS_MNTTAB_H */
