#ifndef AMFI_H_
#define AMFI_H_

#define VERSION "1.2"
// Darwin
#include <mach/mach.h>
#include "unistd.h"

// std
#include <stdio.h>
#include <stdlib.h>

#define RETURN_SIZE 64

#define MSG_ID_DEFAULT 8
#define MSG_ID_COPY_MEM 10

#define GET_KDETAILS 0
#define KREAD 1
#define KWRITE 2
#define CREATE_EMPTY 3
#define SIGN_POINTER 4

#define OP_SUCCESS 0
#define OP_FAIL 1

#define DEALLOCATE 1
#define PERSIST_MEM 0

extern kern_return_t ret;
extern mach_port_t receive_port;

typedef struct
{
  // pointer to newest process in kernel proc_list
  uint64_t allproc;
  // start of kernel mach-o
  uint64_t kbase;
  // kernel aslr
  uint64_t kslide;
  // pointer to newest cdhash in custom trustcache
  uint64_t tcroot;
  // pointer to our pre-defined trustcache slot for one-shot bypassing amfi
  uint64_t cubby;
} KDetails;

typedef struct
{
  mach_msg_header_t header;
  mach_msg_size_t msgh_descriptor_count;
  mach_msg_ool_descriptor_t descriptor;
} OOLMessage;

typedef struct
{
  OOLMessage message;

  // Suitable for use with the default trailer type - no custom trailer
  // information requested using `MACH_RCV_TRAILER_TYPE`, or just the explicit
  // `MACH_RCV_TRAILER_NULL` type.
  mach_msg_trailer_t trailer;
} OOLReceiveMessage;

// server.h prototypes
extern kern_return_t bootstrap_look_up(mach_port_t bootstrap_port, char *service_name, mach_port_t *service_port);
extern kern_return_t bootstrap_register(mach_port_t bootstrap_port, char *service_name, mach_port_t service_port);
extern kern_return_t bootstrap_check_in(mach_port_t bp, const char *service_name, mach_port_t *sp);

// mach.h prototypes
void *mach_alloc(size_t count);
void mach_dealloc(void *buf, size_t size);
mach_msg_return_t receive_ool(OOLReceiveMessage *rcvMessage, mach_msg_timeout_t timeout);
mach_msg_return_t send_ool(mach_port_name_t port, void *addr, mach_msg_size_t size, int deallocate, mach_msg_id_t id);

int init_mach();
void destroy_exit(int error);

// jetsam "bypass" - from kern_memorystatus.h
#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6
int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);

#endif /* server_h */