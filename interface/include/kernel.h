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

// primitives
uint32_t rk32(addr64_t kptr);
uint64_t rk64(addr64_t kptr);
int wk32(addr64_t kptr, uint32_t wbuf);
int wk64(addr64_t kptr, uint64_t wbuf);

// read a kernel pointer - strips PAC
addr64_t read_pointer(addr64_t ptr_addr);

// safely elevate a process
int safe_elevate(pid_t pid);

// find task address for a port
addr64_t find_task_port(mach_port_name_t port);

// find proc struct of program with the pid in the linked list in kernel mem (1 limitation, check error)
addr64_t find_proc(pid_t pid);

// find proc by task - allows for finding child processes (pid > self_pid)
addr64_t find_proc_by_task(pid_t pid);

// find the pid of a program using its name
pid_t find_pid(char *name);

// add entitlements to process
int entitle(pid_t pid, uint32_t target_task_flags, uint32_t target_cs_flags);