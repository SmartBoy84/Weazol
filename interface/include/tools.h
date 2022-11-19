#ifndef TOOLS_H
#define TOOLS_H

#include "kernel.h"
#include <stdio.h>
#include <stdlib.h>

// safely elevate a process
int safe_elevate(pid_t pid);

// rest filesystem root r/w
int test_rw();

#endif