#ifndef _offsetS_H
#define _offsetS_H

// typedef struct
// {
//     uint64_t key;
//     uint64_t value;
// } os_dict_entry_t;

typedef struct
{
    uint64_t key;
    uint64_t value;
} kDictEntry;

typedef struct
{
    uint64_t self_addr;
    uint64_t items_addr;
    uint32_t count;
    uint32_t cap;
    char **names;
    kDictEntry *items;
    char data[0];
} kOSDict;

/* this is the hardcoded kernel image load address (no kaslr slide)
Slide can be found by finding _offset of actual runtime load address (krw_handlers->base) and this
*/
#define __unslidVirtBase 0xFFFFFFF007004000

// flag constants - https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/kern/cs_blobs.h
// proc task flags
#define TF_PLATFORM 0x00000400

// cs flags
#define CS_PLATFORM_BINARY 0x04000000
#define CS_GET_TASK_ALLOW 0x00000004
#define CS_DEBUGGED 0x10000000
#define CS_HARD 0x00000100      /* don't load invalid pages */
#define CS_KILL 0x00000200      /* kill process if it becomes invalid */
#define CS_RESTRICT 0x00000800  /* tell dyld to treat restricted */
#define CS_INSTALLER 0x00000008 /* has installer entitlement */

// proc struc
#define __task_offset 0x10
#define __pid_offset 0x68
#define __ucred_offset 0xF0
#define __flags_offset 0x144
#define __textvp_offset 0x220
#define __cs_flags_offset 0x280

// task struct
#define __vm_map_offset 0x28
#define __thread_offset 0x58
#define __thread_count_offset 0x80
#define __itk_space_offset 0x330
#define __rop_pid_offset 0x360
#define __jop_pid_offset 0x368
#define __bsd_info 0x3A0
#define __task_flags 0x3F4

// thread struct
#define __thread_rop_pid_offset 0x508 // jop - 0x8
#define __thread_jop_pid_offset 0x510
// thread struct
#define __thread_rop_pid_offset 0x508 // jop - 0x8
#define __thread_jop_pid_offset 0x510

#define __ip_receiver_offset 0x60
#define __ip_srights_offset 0xa0
#define __ip_kobject_offset 0x68 // this stores the address to the proc struct in the kernel

// ipc_space
#define __sizeof_ipc_entry_t 0x18
#define __is_table_offset 0x20

// ucred struct
#define __cr_uid_offset 0x18
#define __cr_ruid_offset 0x1c
#define __cr_svuid_offset 0x20

#define __cr_rgid_offset 0x76
#define __cr_svgid_offset 0x7a

#define __cr_label_offset 0x78
#define __cr_audit_offset 0x80
#define __sandbox_slot_offset 0x10 // contains a non-null for sandboxed processes

#define __amfi_slot_offset 0x8

// os_object
#define __os_string_string_offset 0x10
#define __os_string_len_offset 0xc
#define __os_dict_count_offset 0x14
#define __os_dict_dict_entry_offset 0x20

#endif