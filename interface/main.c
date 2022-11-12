#include <stdio.h>
#include "include/jbd.h"
#include "include/kernel.h"

int main(const int argc, char **argv)
{

    if (argc < 2)
    {
        printf("Provide path");
        return 1;
    }

    if (trust_bin(argv + 1, argc - 1))
        printf("Failed");
    else
        printf("Success!");


    KDetails *kdeets;

    if (!(kdeets = init_kdetails()))
    {
        printf("Failed to get kernel details");
        return 1;
    }

    printf("kslide: %llx, kbase: %llx, allproc: %llx", kdeets->kslide, kdeets->kbase, kdeets->allproc);

    pid_t first_pid;

    kread(kdeets->allproc + __pid_offset, &first_pid, sizeof(first_pid));
    printf("my pid: %d, allproc pid %d, my proc: %llx, launchd proc: %llx", find_pid(argv[0]), first_pid, find_proc(find_pid(argv[0])), find_proc(1));

    safe_elevate(find_pid(argv[0]));

    printf("\n%s", (read_pointer(read_pointer(find_task_port(mach_task_self()) + __ip_kobject_offset) + __bsd_info) == find_proc(getpid()))
                       ? "[*] task_port found"
                       : "Huh? You got the wrong task_port my friend");

    return 0;
}