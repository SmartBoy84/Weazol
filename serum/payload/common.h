#include <stdio.h>
#include <spawn.h>
#include "include/tools.h"
#include "include/kernel.h"
#include <string.h>
#include <pthread.h>
#include <unistd.h>

// testing
#include "include/machapi.h"

extern pspawn_t orig_pspawn, orig_pspawnp;

char *get_name();

int fake_posix_spawn_common(pid_t *restrict pid, const char *restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict], pspawn_t origfunc);
int fake_posix_spawn(pid_t *restrict pid, const char *restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict]);
int fake_posix_spawnp(pid_t *restrict pid, const char *restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict]);