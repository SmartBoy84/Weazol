#ifndef JBD_H_
#define JBD_H_

#include "machapi.h"
#include <stdio.h>
#include <sys/stat.h>
#include "mach/mach.h"
#include "string.h"

#define server_name "com.fugu.amfi"
#define launchctl "/.Fugu14Untether/bin/launchctl"
#define amfidebilitate "/.Fugu14Untether/amfi/amfidebilitate"
#define amfiplist "/.Fugu14Untether/amfi/com.fugu.debilitate.plist"

#define TIMEOUT 100 // ms

#define TC_SUB_IN 1
#define TC_CREATE_NEW 0

extern int logging;

// init mach shizzle
int init_me();

// get kdetails struct
KDetails *init_kdetails();

// read from memory
int kread(uint64_t ptr, void *buff, uint64_t count);

// write to memory
int kwrite(uint64_t ptr, void *rbuff, uint64_t count);

// create a trustcache of defined length
uint64_t create_empty(int count);

// sign a pointer (pac bypass)
uint64_t sign_pointer(uint64_t target_p, uint64_t current_p);

#endif