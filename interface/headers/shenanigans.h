#ifndef _shenanigans_H
#define _shenanigans_H

#include <mach/mach.h>
#include <sys/param.h> // literall only for MAX_PATH_LEN

#define DYLD_INTERPOSE(_replacment, _replacee) \
    static struct                              \
    {                                          \
        const void *replacment;                \
        const void *replacee;                  \
    } _interpose_##_replacee                   \
        __attribute__((used)) __attribute__((section("__DATA,__interpose"))) = {&_replacment, &_replacee};

#define PROC_PIDPATHINFO_MAXSIZE (4 * MAXPATHLEN)

int csops(pid_t pid, unsigned int ops, uint32_t *useraddr, size_t usersize);

extern int proc_listallpids(void *, int);
extern int proc_pidpath(int, void *, uint32_t);

// https://github.com/darlinghq/darling-newlkm/blob/master/osfmk/vm/pmap.h
typedef struct {
        uint32_t version;
        char uuid[16];
        uint32_t size;
} trustcache_header;

typedef struct // pmap_image4_trust_cache
{
    addr64_t next; // linked list
    addr64_t module; // unneeded, points to ourselves

    trustcache_header header;
} kern_tc;

#endif