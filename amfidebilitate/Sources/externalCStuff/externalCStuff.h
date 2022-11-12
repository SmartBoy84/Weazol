//
//  externalCStuff.h
//  jailbreakd - externalCStuff
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

#ifndef externalCStuff_h
#define externalCStuff_h

#include <sys/snapshot.h>
#include <spawn.h>
#include <mach/mach.h>
#include <ptrauth.h>

typedef struct val_attrs
{
    uint32_t length;
    attribute_set_t returned;
    uint32_t error;
    attrreference_t name_info;
    char *name;
    fsobj_type_t obj_type;
} val_attrs_t;

int posix_spawnattr_set_persona_np(const posix_spawnattr_t *__restrict, uid_t, uint32_t);
int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t *__restrict, uid_t);
int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t *__restrict, gid_t);

uint64_t reboot3(uint64_t how, uint64_t unk);

#define PROC_ALL_PIDS 1U
int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
int proc_listallpids(void *buffer, int buffersize);
int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

kern_return_t mach_vm_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, const uint8_t *data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, uint8_t *data, mach_vm_size_t *outsize);

#endif /* externalCStuff_h */
