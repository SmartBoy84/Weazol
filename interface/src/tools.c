#include "include/tools.h"
#include "include/kernel.h"
#include "include/jbd.h"

// for the noobs
int run(char *path, char *arg1, char *arg2, char *arg3, pspawn_t custom_func) // mostly acts as a shim for past code
{
    char const *launch_arg[] = {path, arg1, arg2, arg3};
    return posix_custom(NULL, path, NULL, NULL, (char **)&launch_arg, NULL, custom_func, EXEC_WAIT | ENTITLE);
}

int posix_custom(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *const *argv, char *const *envp, pspawn_t custom_func, uint32_t flags)
{
    // big man
    char **newenvp;
    if (flags & INJECT_PAYLOAD)
    {
        int envcount = 0;
        int dyld_i = 0;

        if (envp != NULL)
        {
            const char **currentenv = envp;
            int dyld_finder = 0;

            for (int i = 0; *currentenv != NULL; i++)
            {
                if (strstr(*currentenv, "DYLD_INSERT_LIBRARIES") == NULL)
                    envcount++;
                else
                    dyld_i = i; // store where this is defined

                currentenv++;
            }
        }

        newenvp = malloc((envcount + 2) * sizeof(char **)); // +2 - store DYLD_INSERT_LIBRARIES + NULL
        int j = 0;                                          // newenvp counter
        for (int i = 0; i < envcount; i++)
        {
            if (strstr(envp[i], "DYLD_INSERT_LIBRARIES"))
                continue;

            newenvp[j++] = envp[i];
        }

        char *injection = malloc(strlen("DYLD_INSERT_LIBRARIES=") + strlen(PSPAWN_PAYLOAD) + 1);
        injection[0] = '\0';
        strcat(injection, "DYLD_INSERT_LIBRARIES=");
        strcat(injection, PSPAWN_PAYLOAD);

        newenvp[j] = injection;
        newenvp[++j] = NULL;
    }
    else
        newenvp = envp;

    int status;

    if (pid == NULL)
        pid = malloc(sizeof(int));

    if (attrp == NULL)
    {
        attrp = malloc(sizeof(posix_spawnattr_t));
        status = posix_spawnattr_init(attrp);
        status = status != 0 ? status : posix_spawnattr_setflags(attrp, POSIX_SPAWN_START_SUSPENDED);
    }
    else
    {
        short flags;
        status = posix_spawnattr_getflags(attrp, &flags);
        flags |= POSIX_SPAWN_START_SUSPENDED;
        status = status != 0 ? status : posix_spawnattr_setflags(attrp, flags);
    }

    if (status != 0)
    {
        perror("can't set flags");
        return status;
    }

    status = custom_func != NULL ? custom_func(pid, path, file_actions, attrp, argv, newenvp) : posix_spawn(pid, path, file_actions, attrp, argv, newenvp);
    if (status != 0)
    {
        printf("posix_spawn [ERROR]: %s %d for %s\n", strerror(status), status, path);
        return status;
    }

    if (flags & ENTITLE)
    {
        entitle(*pid, TF_PLATFORM, CS_PLATFORM_BINARY | CS_GET_TASK_ALLOW | CS_DEBUGGED | CS_INSTALLER); // unc0ver does this to processes, possible add CS_INSTALLER ent
        // pacify(1, *pid);                                                        // BROKEN, not necessary - necessary for tweak injection - from the payload, this will set all process's PAC keys to be the same as launchd
    }

    kill(*pid, SIGCONT);

    if (flags & EXEC_WAIT)
        wait(&status);

    printf("%s exited with status %d\n", path, WEXITSTATUS(status));
    return WEXITSTATUS(status);
}

int safe_elevate(pid_t pid)
{
    addr64_t ucred_s = read_pointer(find_proc(pid) + __ucred_offset);

    if (!ucred_s)
    {
        printf("Failed to read my ucred struct\n");
        return 1;
    }

    if (wk32(ucred_s + __cr_svuid_offset, 0))
    {
        printf("Ucred writing failed!");
        return 1;
    }

    // yes, setuid(0) need to be called twice - from taurine
    if (setuid(0) || setuid(0) || setgid(0) || getuid()) // apparently this just works after nulling __cs_svuid??
    {
        printf("Elevation failed :( UID: %d ", getuid());
        return 1;
    }

    printf("I'm freeee - UID: %d ", getuid());
    return 0; // apparently getting root is enough to break out of sandbox?
}

int test_rw()
{
    const char *name = "/test.txt";
    FILE *fptr = fopen(name, "w+");

    char string[] = "hello world!";
    char *buffer = malloc(sizeof(string));

    int status = 1;

    if (!fptr || !fwrite(string, sizeof(char), sizeof(string), fptr))
        printf("Failed to write to root! :(\n");
    else
    {
        fflush(fptr);
        fseek(fptr, 0, SEEK_SET);

        if (!fread(buffer, sizeof(char), sizeof(string), fptr))
            printf("failed to read file from root! :( \n");
        else if (strcmp(string, buffer))
            printf("Partial r/w?? wrote: %s but read %s\n", string, buffer);
        else
        {
            status = 0;
            printf("R/W works!");
        }

        if (fclose(fptr) || remove(name))
        {
            printf("Error closing/removing file...");
            fclose(fptr);
        }
    }

    return status;
}