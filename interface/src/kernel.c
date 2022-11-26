#include "include/kernel.h"
#include "include/jbd.h"

uint32_t rk32(addr64_t kptr)
{
    uint32_t buff = 0;
    kread(kptr, &buff, sizeof(uint32_t));
    return buff;
}

uint64_t rk64(addr64_t kptr)
{
    uint64_t buff = 0;
    kread(kptr, &buff, sizeof(uint64_t));
    return buff;
}

int wk32(addr64_t kptr, uint32_t wbuf)
{
    return kwrite(kptr, &wbuf, sizeof(uint32_t));
}

int wk64(addr64_t kptr, uint64_t wbuf)
{
    return kwrite(kptr, &wbuf, sizeof(uint64_t));
}

addr64_t read_pointer(addr64_t ptr_addr)
{
    addr64_t ptr;
    if (kread(ptr_addr, &ptr, sizeof(addr64_t)))
    {
        printf("Failed to read pointer!");
        return 0;
    }

    return STRIP_PAC(ptr);
}

addr64_t find_task_port(mach_port_name_t port)
{
    // from here: https://github.com/jakeajames/multi_path/blob/master/multi_path/jelbrek/kern_utils.m

    KDetails *kdeets = init_kdetails();
    addr64_t curproc = kdeets->allproc;

    addr64_t my_task_addr = read_pointer(find_proc(getpid()) + __task_offset);

    uint64_t itk_space, is_table = 0;

    // From our proc -> task_struct -> itk_space (ports)
    if ((!(itk_space = read_pointer(my_task_addr + __itk_space_offset))) ||
        (!(is_table = read_pointer(itk_space + __is_table_offset))))
    {
        printf("Failed to read task details\n");
        return 0;
    }

    // get this process's mach port
    uint32_t port_index = port >> 8;

    // Now read the address associated with our port in the itk_space (just use our own processes port space)
    addr64_t port_addr = 0;
    if (!(port_addr = read_pointer(is_table + (port_index * __sizeof_ipc_entry_t))))
    {
        printf("So close! Failed to read port_addr");
        return 0;
    }

    return port_addr;

    /* ipc_entry defined here:
    (https://opensource.apple.com/source/xnu/xnu-201/osfmk/ipc/ipc_entry.h.auto.html)
    more here: https://github.com/maximehip/mach_portal
    basically this is used to map the port name (userland representation) to the port object (kernel representation)*/
}

addr64_t find_proc(pid_t pid)
{
    KDetails *kdeets = init_kdetails();
    addr64_t curproc = kdeets->allproc;

    pid_t tpid;
    for (;;)
    {
        if (kread(curproc + __pid_offset, &tpid, sizeof(tpid)))
            break;

        if (tpid == pid)
            return curproc;

        if (!(curproc = read_pointer(curproc)))
            break;
    }

    printf("Failed to find pid (can only find structs of programs launched "
           "before current running)\n");
    return 0;
}

pid_t find_pid(char *name)
{
    KDetails *kdeets = init_kdetails();
    addr64_t curproc = kdeets->allproc;

    pid_t tpid;
    char path_buffer[MAXPATHLEN];

    for (;;)
    {
        if (kread(curproc + __pid_offset, &tpid, sizeof(tpid))) // better than 1...0xFFF
            break;

        if (proc_pidpath(tpid, (void *)path_buffer, sizeof(path_buffer)) < 0)
        {
            printf("(%s:%d) proc_pidpath() call failed.\n", __FILE__, __LINE__);
            continue;
        }

        if (strstr(path_buffer, basename(name)))
            return tpid;

        if (kread(curproc, &curproc, sizeof(curproc)))
            break;
    }

    printf("Failed to find process %s :(", name);
    return -1;
}

addr64_t find_proc_by_task(pid_t pid)
{
    // this method required task_for_pid entitlement

    mach_port_t task = 0;

    kern_return_t kern_return = task_for_pid(mach_task_self(), pid, &task);
    if (kern_return != KERN_SUCCESS)
    {
        printf("task_for_pid failed: %s\n", mach_error_string(kern_return));
        return 0;
    }

    addr64_t task_port_addr;
    if (!(task_port_addr = find_task_port(task)))
        return 0;

    addr64_t task_addr;
    if (!(task_addr = read_pointer(task_port_addr + __ip_kobject_offset)))
        return 0;

    addr64_t proc = read_pointer(task_addr + __bsd_info);
    if (proc == 0)
    {
        printf("Failed to find proc for pid %d", pid);
        return 0;
    }
    mach_port_deallocate(mach_task_self(), task);
    return proc;
}

// int add_entitlement() {
    
// }

int entitle(pid_t pid, uint32_t target_task_flags, uint32_t target_cs_flags)
{
    uint64_t target_proc = 0;
    if (!(target_proc = pid == getpid() ? find_proc(getpid()) : find_proc_by_task(pid)))
    {
        printf("Failed to find child proc");
        return 1;
    }

    addr64_t our_task_addr = read_pointer(target_proc + __task_offset);
    addr64_t task_flags_addr = our_task_addr + __task_flags;
    addr64_t csflags_addr = target_proc + __cs_flags_offset;

    uint32_t flags = rk32(task_flags_addr);
    flags |= target_task_flags;
    wk32(task_flags_addr, flags | target_task_flags);

    uint32_t csflags = rk32(csflags_addr);

    csflags |= target_cs_flags;
    csflags &= ~(CS_RESTRICT | CS_HARD | CS_KILL); // remove impediments
    wk32(csflags_addr, csflags);

    return 0;
}

void pacify(pid_t source, pid_t target)
{
    // jop is included for completion's sake but it seems all processes have jop_id = 0xFEEDFACE
    addr64_t source_task = read_pointer(find_proc_by_task(source) + __task_offset);
    addr64_t target_task = read_pointer(find_proc_by_task(target) + __task_offset);

    uint64_t source_jop = rk64(source_task + __jop_pid_offset);
    uint64_t target_jop = rk64(target_task + __jop_pid_offset);

    uint64_t target_rop = rk64(target_task + __rop_pid_offset);
    uint64_t source_rop = rk64(source_task + __rop_pid_offset);

    wk64(target_task + __jop_pid_offset + sizeof(uint64_t), source_rop);
    wk64(target_task + __jop_pid_offset, source_jop);

    uint32_t thread_count = rk32(target_task + __thread_count_offset);
    addr64_t target_thread = 0;

    for (int i = 0; i < thread_count; i++)
    {
        target_thread = read_pointer(i == 0 ? target_task + __thread_offset : target_thread);

        wk64(target_thread + __thread_jop_pid_offset, source_jop);
        wk64(target_thread + __thread_rop_pid_offset, target_rop);
    }
}