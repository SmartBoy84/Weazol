#ifndef _iosurface_H
#define _iosurface_H

#include <assert.h>
#include <sys/sysctl.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "mach/mach.h"
#include <CoreFoundation/CoreFoundation.h>

#include "IOKit/IOKitLib.h"
#define arrayn(array) (sizeof(array) / sizeof((array)[0]))

extern mach_port_t IOSurface_worker_uc;
extern uint32_t IOSurface_worker_id;

bool IOSurface_init();
uint32_t iosurface_create_fast();

#endif