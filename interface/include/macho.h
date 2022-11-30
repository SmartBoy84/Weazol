#ifndef MACHO_H_
#define MACHO_H_

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <mach-o/loader.h>
#include <sys/types.h>
#include <unistd.h>
#include "mach-o/arch.h"

// get mach-o header from kernel or file
struct mach_header_64 * get_header(pid_t pid, char *path);
// get load segments - NULL capped
struct load_command** load_lcmds(pid_t pid, char *path, int mode);
// get list of all dynamically linked libraries - NULL capped
char **get_dylibs(pid_t pid, char *path);

#endif