#include <mach/mach.h>
#include <sys/param.h> // literall only for MAX_PATH_LEN

#define DYLD_INTERPOSE(_replacment, _replacee) \
    static struct { const void* replacment; const void* replacee; } _interpose_##_replacee \
    __attribute__((used)) __attribute__((section("__DATA,__interpose"))) = { &_replacment, &_replacee };

#define PROC_PIDPATHINFO_MAXSIZE (4 * MAXPATHLEN)

extern int proc_listallpids(void *, int);
extern int proc_pidpath(int, void *, uint32_t);