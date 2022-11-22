#ifndef JBD_H_
#define JBD_H_

#include "machapi.h"
#include <stdio.h>
#include <sys/stat.h>
#include "mach/mach.h"
#include "string.h"
#include <spawn.h>
#include <signal.h>

#define TIMEOUT 100 // ms
#define TRUST_BIN "/binpack/opainject"
#define PSPAWN_PAYLOAD "/binpack/vamos.dylib"

// complicated shizzle
typedef int (*pspawn_t)(pid_t *restrict pid, const char *restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict]);

int init_me();

// shortcut to posixspawn
int run(char *path, char *arg1, char *arg2, char *arg3, pspawn_t custom_func);

// my custom posix_spawn
int posix_custom(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *const *argv, char *const *envp, pspawn_t custom_func, int execution_end_wait);

// add a binary to trustcache!
int trust_bin(char **path, int path_n);

// get kdetails struct
KDetails *init_kdetails();

// read from memory
int kread(uint64_t ptr, void *buff, uint64_t count);

// write to memory
int kwrite(uint64_t ptr, void *rbuff, uint64_t count);

// get base of the predefined temp trustcache
uint64_t get_tc_base();

// sub in hash to temp trustcache (avoids me having to do kern r/w)
int sub_hash(uint8_t *hash, int mem_handle);

// add list of hashs
uint64_t add_hashs(uint8_t *hashes, uint8_t count, int mem_handle);

// create a trustcache of defined length
uint64_t create_empty(int count);

// sign a pointer (pac bypass)
uint64_t sign_pointer(uint64_t target_p, uint64_t current_p);

#endif