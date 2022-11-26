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

#define CHECK_FLAG(a, b) (((a & b) > 0) ? 1 : 0)
// custom posix_spawn flags
#define INJECT_PAYLOAD (1) /* inject posix_spawn hook */
#define EXEC_WAIT (1 << 1) /* wait for child process to exit */
#define ENTITLE (1 << 2)   /* give child process standard entitlements (remember to add others) */
#define WAS_EXEC (1 << 3)  /* this child process is exec'd */

#define DYLD_VAR "DYLD_INSERT_LIBRARIES="
#define ENV_VAR "CUSTOM_POSIX_FLAGS="

// for custom pspawn
typedef int (*pspawn_t)(pid_t *restrict pid, char *restrict path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *restrict attrp, char *argv[restrict], char *envp[restrict]);

// shortcut to posixspawn
int run(char *path, char *arg1, char *arg2, char *arg3, pspawn_t custom_func);

// gen custom flags
char *gen_flags(unsigned long flags);

// add our variable to the environment value
char **add_var(char **envp, uint32_t flags);

// my custom posix_spawn
int posix_custom(pid_t *pid, char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char **argv, char **envp, pspawn_t custom_func, uint32_t flags);

// utilise a double fork to detach process from parent
void daemonize_me();

// safely elevate a process
int safe_elevate(pid_t pid);

// rest filesystem root r/w
int test_rw();

#endif