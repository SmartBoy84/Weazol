#include "include/tools.h"
#include "include/kernel.h"
#include "include/jbd.h"
#include "include/cdhash.h"
#include "headers/shenanigans.h"

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
    int env_i = 0;

    char **newenvp;

    if (envp != NULL)
    {
        for (int i = 0; envp[i] != NULL; i++)
        {
            if (strstr(envp[i], DYLD_VAR))
                dyld_i = i;
            else if (strstr(envp[i], ENV_VAR))
                env_i = i;

            size_c++;
        }

        size_c += dyld_i == 0 && CHECK_FLAG(flags, INJECT_PAYLOAD); // add 1 if dyld_stock wasn't already found and INJECT_PAYLOAD is set
        size_c += env_i == 0;

        newenvp = malloc((size_c + 1) * sizeof(char **)); // possible memory leak? hopefully posix_spawn deallocates these else we're screwed - it doesn't
        memcpy(newenvp, envp, size_c * sizeof(char **));
    }
    else
    {
        size_c = 1 + 1 + CHECK_FLAG(flags, INJECT_PAYLOAD);
        dyld_i = 0;

        newenvp = malloc(size_c * sizeof(char **));
    }

    newenvp[size_c - 2] = env_i ? envp[env_i] : gen_flags(flags); // store our flags at the end for whomever may need it
    newenvp[size_c - 1] = NULL;                                   // set last variable to NULL

    if (CHECK_FLAG(flags, INJECT_PAYLOAD))
        newenvp[dyld_i] = gen_var(DYLD_VAR, PSPAWN_PAYLOAD); // a bit destructive but DYLD_INTERPOSING really shouldn't be done anywhere else - for now

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

int trust_bin(char **path, int path_n, int sub)
{
    KDetails *kdeets = init_kdetails();
    int ret = 1; // expect failure

    cdhash_list *cdhash_master = malloc(sizeof(cdhash_list) * path_n);
    int count = 0; // number of valid cdhashes
    int size = 0;  // each cdhash struct can contain multiple hashes

    cdhash_header *temp_tc = malloc(sizeof(cdhash_header));
    addr64_t newest_tc = read_pointer(kdeets->tcroot); // reads pointer to cdhash that is the latest at this point

    for (int i = 0; i < path_n; i++)
    {
        struct stat sb = {0};
        if (stat(path[i], &sb) != 0)
        {
            printf("Failed to open bin %s", path[i]);
            cdhash_master[i].count = 0;
            continue;
        }

        if (!S_ISREG(sb.st_mode))
        {
            printf("%s isn't a binary!", path[i]);
            cdhash_master[i].count = 0;
            continue;
        }

        cdhash *c;
        int ret_count = find_cdhash(path[i], sb.st_size, &c);

        if (ret_count == 0)
        {
            printf("cdhash for %s not found", path[i]);
            continue;
        }

        // check if it's already in custom trustcache
        addr64_t tc_ptr = newest_tc;
        size_t found_hash_size = sizeof(cdhash) * ret_count;

        while (!kread(tc_ptr, temp_tc, sizeof(cdhash_header)))
        {
            if (temp_tc->count < ret_count)
            {
                tc_ptr = read_pointer(temp_tc->next);
                continue;
            }

            tc_ptr += sizeof(cdhash_header);

            size_t tc_hash_size = sizeof(cdhash) * temp_tc->count;
            cdhash *hash = malloc(tc_hash_size);

            if (!kread(tc_ptr, hash, tc_hash_size))
            {
                if (memmem(hash, tc_hash_size, c, found_hash_size) != NULL) // -1 -- for some reason the last byte fluctuates, kernel shizzle?
                {
                    free(hash);
                    goto found;
                }
            }

            free(hash);
            tc_ptr = read_pointer(temp_tc->next);
        }

        cdhash_master[i].count = ret_count;
        cdhash_master[i].cdhash = c;

        count++;
        size += ret_count;
        continue; // don't free() since the hash pointer will be stored in the buffer

    found: // we come here when it's hash is found to be already in custom trustcache
        free(c);
    }

    if (size == 0)
        goto end;

    size_t entry_size = sizeof(cdhash_header) + (sizeof(cdhash) * size);
    cdhash_entry *entry = malloc(entry_size);

    cdhash *c_ptr = &(entry->cdhash);

    for (int i = 0; i < count; i++)
    {
        if (cdhash_master[i].count > 0)
        {
            memcpy(c_ptr, cdhash_master[i].cdhash, sizeof(cdhash) * cdhash_master[i].count);
            free(cdhash_master[i].cdhash);
            c_ptr += cdhash_master[i].count;
        }
    }
    printf("Size %d", size);
    // for (int x = 0; x < size; x++)
    // {
    //     for (int i = 0; i < sizeof(cdhash); i++)
    //     {
    //         printf("%d ", *(((uint8_t *)&entry->hash) + (x * sizeof(cdhash)) + i));
    //     }
    //     printf("\n");
    // }

    uint64_t tc_addr = 0;
    if (size == 1 && sub == TC_SUB_IN)
        tc_addr = kdeets->cubby;
    else
        tc_addr = create_empty(size);

    if (!tc_addr)
        printf("Failed to create/find trustcache in kernel");
    else
    {
        if (kread(tc_addr, entry, sizeof(cdhash_header)) || // fugu does all the header shenanigans for us
            kwrite(tc_addr, entry, entry_size))
            printf("Failed to read/write hash");
        else
            ret = 0; // Success!
    }

    free(entry); // it's placement here isn't a mistake, look carefully

    if (ret == 1)
        printf("Failed to add hash!");

end:
    free(temp_tc);
    free(cdhash_master);

    return ret;
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