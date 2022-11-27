#include "include/tools.h"
#include "include/kernel.h"
#include "include/jbd.h"

// for the noobs
int run(char *path, char *arg1, char *arg2, char *arg3, pspawn_t custom_func) // mostly acts as a shim for past code
{
    char *launch_arg[] = {path, arg1, arg2, arg3};
    return posix_custom(NULL, path, NULL, NULL, (char **)&launch_arg, NULL, custom_func, EXEC_WAIT | ENTITLE); // don't inject payload
}

char *gen_var(char *name, char *val)
{
    size_t size = strlen(name) + strlen(val) + 2; // 1 is for ;, 1 for \0
    char *target = malloc(size);

    target[0] = '\0';
    strcat(target, name);
    strcat(target, val);

    target[size - 1] = ';'; // add ; at the end, AFTER \0

    return target;
}

char *gen_flags(unsigned long flags)
{
    char str[32]; // eek, hopefully this is enough?
    sprintf(str, "%luend", flags);

    return gen_var(ENV_VAR, str);
}

char **add_var(char **envp, uint32_t flags)
{
    // aight, you need to do a lot of free() here bro
    // structure if envp!=NULL: [...envp, CUSTOM_POSIX_FLAGS, NULL]
    // if envp == NULL: [DYLD_INSERT?, CUSTOM_POSIX_FLAGS, NULL]

    int size_c = 0;
    int dyld_i = 0;
    char **newenvp;

    if (envp != NULL)
    {
        for (int i = 0; envp[i] != NULL; i++)
        {
            if (strstr(envp[i], DYLD_VAR))
                dyld_i = i;

            size_c++;
        }

        size_c += dyld_i == 0 && CHECK_FLAG(flags, INJECT_PAYLOAD); // add 1 if dyld_stock wasn't already found and INJECT_PAYLOAD is set

        newenvp = malloc((size_c + 2) * sizeof(char **)); // possible memory leak? hopefully posix_spawn deallocates these else we're screwed - it doesn't
        memcpy(newenvp, envp, size_c * sizeof(char **));
    }
    else
    {
        size_c = 1 + 1 + CHECK_FLAG(flags, INJECT_PAYLOAD);
        dyld_i = 0;

        newenvp = malloc(size_c * sizeof(char **));
    }

    newenvp[size_c - 2] = gen_flags(flags); // store our flags at the end for whomever may need it
    newenvp[size_c - 1] = NULL;             // set last variable to NULL

    if (CHECK_FLAG(flags, INJECT_PAYLOAD))
        newenvp[dyld_i] = gen_var(DYLD_VAR, PSPAWN_PAYLOAD); // a bit destructive but DYLD_INTERPOSING really shouldn't be done anywhere else

    return newenvp;
}

int posix_custom(pid_t *pid, char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char **argv, char **envp, pspawn_t custom_func, uint32_t flags)
{
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
        flags |= POSIX_SPAWN_START_SUSPENDED; // we may soon be able to remove this entirely
        status = status != 0 ? status : posix_spawnattr_setflags(attrp, flags);
    }

    if (status != 0)
    {
        perror("can't set flags");
        return status;
    }

    char **newenvp = add_var(envp, flags);
    status = custom_func != NULL ? custom_func(pid, path, file_actions, attrp, argv, newenvp) : posix_spawn(pid, path, file_actions, attrp, argv, newenvp);
    if (status != 0)
    {
        printf("posix_spawn [ERROR]: %s %d for %s\n", strerror(status), status, path);
        return status;
    }

    if (flags & ENTITLE)
    {
        printf("Entitling...");
        entitle(*pid, TF_PLATFORM, CS_PLATFORM_BINARY | CS_GET_TASK_ALLOW | CS_DEBUGGED | CS_INSTALLER); // unc0ver does this to processes, possible add CS_INSTALLER ent
        // pacify(1, *pid);                                                        // BROKEN, not necessary - necessary for tweak injection - from the payload, this will set all process's PAC keys to be the same as launchd
    }

    kill(*pid, SIGCONT);

    if (flags & EXEC_WAIT)
        wait(&status);

    printf("%s (pid: %d) exited with status %d\n", path, *pid, WEXITSTATUS(status));
    return WEXITSTATUS(status);
}

void daemonize_me()
{
    pid_t pid;

    // fork off the parent process
    pid = fork();
    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS);
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    // ignore fatal kill signals
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    // second fork
    pid = fork();
    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS);
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    umask(0);                                        // set new file perms
    chdir("/");                                      // change working dir to root
    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) // Close all open file descriptors
        close(x);
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