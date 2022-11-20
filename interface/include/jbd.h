#include "machapi.h"
#include <stdio.h>
#include <sys/stat.h>
#include "mach/mach.h"
#include "string.h"

#define TIMEOUT 100 // ms

int init_me();

// shortcut to posixspawn
int run(char *path, char *arg1, char *arg2, char *arg3);

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