#include <mach/mach.h>

extern int proc_listallpids(void *, int);
extern int proc_pidpath(int, void *, uint32_t);