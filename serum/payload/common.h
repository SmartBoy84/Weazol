#ifndef COMMON_HOOK_H_
#define COMMON_HOOK_H_

// standard
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

// hooks
#include <spawn.h>
#include "dlfcn.h"

// my API
#include "include/machapi.h"
#include "include/tools.h"
#include "include/kernel.h"
#include "include/jbd.h"

#define xpcproxy "/usr/libexec/xpcproxy"

// this is set in uinstd.h
extern char **environ;

// this is set in include/jbd.h
extern int logging;

// hooked function type definitions for fishook
typedef int (*pspawn_t)(pid_t *pid, char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *argv[], char *envp[]);
typedef int (*execve_t)(char *pathname, char *argv[], char *envp[]);
typedef void *(*dlopen_t)(char *filename, int flag);

extern dlopen_t orig_dlopen;
extern pspawn_t orig_pspawn, orig_pspawnp;

// the reason I can do this is because the arguments "overlap" rather than "override"
extern execve_t orig_execve, orig_execv, orig_execvp; // yes I know these functions may not seem to be compatible but bear with me

char *get_name();

// hooks
void *fake_dlopen(char *filename, int flag);
int fake_posix_spawn_common(pid_t *pid, char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *argv[], char *envp[], pspawn_t origfunc);
int fake_posix_spawn(pid_t *pid, char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *argv[], char *envp[]);
int fake_posix_spawnp(pid_t *pid, char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *argv[], char *envp[]);
int fake_execve(char *pathname, char *argv[], char *envp[]);
int fake_execv(char *path, char *argv[]);
int fake_execvp(char *file, char *argv[]);

#endif