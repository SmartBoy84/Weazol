#ifndef COMMON_HOOK_H_
#define COMMON_HOOK_H_

#include <stdio.h>
#include <spawn.h>
#include "include/tools.h"
#include "include/kernel.h"
#include <string.h>
#include <pthread.h>
#include <unistd.h>

// testing
#include "include/machapi.h"

#define xpcproxy "/usr/libexec/xpcproxy"

// hooked function type definitions for fishook
typedef int (*pspawn_t)(pid_t * pid, char * path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t * attrp, char *argv[], char *envp[]);
typedef int (*execve_t)(char *pathname, char *argv[], char *envp[]);

extern pspawn_t orig_pspawn, orig_pspawnp;
extern execve_t orig_execve;

char *get_name();

// hooks
int fake_posix_spawn_common(pid_t * pid, char * path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t * attrp, char *argv[], char *envp[], pspawn_t origfunc);
int fake_posix_spawn(pid_t * pid, char * path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t * attrp, char *argv[], char *envp[]);
int fake_posix_spawnp(pid_t * pid, char * path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t * attrp, char *argv[], char *envp[]);
int fake_execve(char *pathname, char *argv[], char *envp[]);

#endif