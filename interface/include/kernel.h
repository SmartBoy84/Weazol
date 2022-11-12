#include "jbd.h"
#include "headers/offsets.h"
#include "headers/shenanigans.h"
#include <string.h>
#include <stddef.h>
#include <sys/param.h> // literall only for MAX_PATH_LEN
#include <libgen.h>    // literally only for basename

// this way of krw over mach OOL is VERY fast however the startup is slow due to port init/register/find

// strip pointer authentication codes (PAC) from signed pointers (arm64e)
#define STRIP_PAC(ptr) (ptr | 0xFFFFFF8000000000)

// safely elevate a process
int safe_elevate(pid_t pid);

// read a kernel pointer - strips PAC
addr64_t read_pointer(addr64_t ptr_addr);

// find task address for a port
addr64_t find_task_port(mach_port_name_t port);

// find proc struct of program with the pid in the linked list in kernel mem (1 limitation, check error)
addr64_t find_proc(pid_t pid);

// find the pid of a program using its name
pid_t find_pid(char *name);