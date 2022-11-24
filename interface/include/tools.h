#ifndef TOOLS_H_
#define TOOLS_H_

#include "kernel.h"
#include <stdio.h>
#include <stdlib.h>
#include <spawn.h>
#include <signal.h>

// integral file locations
#define TRUST_BIN "/binpack/trust"
#define INJECT_BIN "/binpack/opainject"
#define PSPAWN_PAYLOAD "/binpack/dyld_vamos.dylib"
#define FISHOOK_PSPAWN_PAYLOAD "/binpack/fishook_vamos.dylib"

// custom posix_spawn flags
#define INJECT_PAYLOAD (1) /* inject posix_spawn hook */
#define EXEC_WAIT (1 << 1) /* wait for child process to exit */
#define ENTITLE (1 << 2)   /* give child process standard entitlements (remember to add others) */

// posix type definitions for fishook
typedef int (*pspawn_t)(pid_t *restrict pid, const char *restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict]);

// shortcut to posixspawn
int run(char *path, char *arg1, char *arg2, char *arg3, pspawn_t custom_func);

// my custom posix_spawn
int posix_custom(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *const *argv, char *const *envp, pspawn_t custom_func, uint32_t flags);

// safely elevate a process
int safe_elevate(pid_t pid);

// rest filesystem root r/w
int test_rw();

#endif