#include "include/jbd.h"
#include "include/cdhash.h"
#include <spawn.h>

mach_port_t server = 0;
#define server_name "com.fugu.amfi"
#define amfidebilitate_path "/.Fugu14Untether/autorun/amfidebilitate"

void run(char *path, char *arg1, char *arg2, char *arg3)
{
    const char *launch_arg[] = {path, arg1, arg2, arg3};
    pid_t pid;

    posix_spawn(&pid, path, NULL, NULL, (char **)&launch_arg, NULL);
    // waitpid(pid, NULL, 0);
}

void init_me()
{
    init_mach();

    if (server == 0)
    {
        if (bootstrap_look_up(server, server_name, &server) != MACH_MSG_SUCCESS) // always done on a mach op to ensure amfidebilitate is running
        {
            printf("Failed to get server port - HOW?! Hang on, I'll try to start it...");
            run(amfidebilitate_path, NULL, NULL, NULL);
        }
        // destroy_exit(EXIT_FAILURE);
    }
}

int trust_bin(char **path, int path_n)
{
    cdhash_list *cdhash_master = malloc(sizeof(cdhash_list) * path_n);
    int count = 0; // number of valid cdhashes
    int size = 0;  // each cdhash struct can contain multiple hashes

    for (int i = 0; i < path_n; i++)
    {
        struct stat sb = {0};
        if (stat(path[i], &sb) != 0)
        {
            printf("Failed to open binary");
            cdhash_master[i].count = 0;
            continue;
        }

        if (!S_ISREG(sb.st_mode))
        {
            printf("Not a binary!");
            cdhash_master[i].count = 0;
            continue;
        }

        printf("Computing hash for %s", path[i]);

        cdhash *c;
        int ret_count = find_cdhash(path[i], sb.st_size, &c);

        cdhash_master[i].count = ret_count;
        cdhash_master[i].hash = c;

        count++;
        size += ret_count;
    }
    printf("Found %d valid hashes, adding", count);

    cdhash *c = malloc(sizeof(cdhash) * size);
    cdhash *c_ptr = c;

    for (int i = 0; i < count; i++)
    {
        if (cdhash_master[i].count > 0)
        {
            memcpy(c_ptr, cdhash_master[i].hash, sizeof(cdhash) * cdhash_master[i].count);
            c_ptr += cdhash_master[i].count;
        }
    }

    printf("Count: %d\n", count);
    for (int x = 0; x < size; x++)
    {
        for (int i = 0; i < sizeof(cdhash); i++)
        {
            printf("%d ", *((uint8_t *)(c + x) + i));
        }
        printf("\n");
    }

    int ret = 0;

    if (size == 1)
        ret = sub_hash((uint8_t *)c, PERSIST_MEM);
    else if (size > 1)
        ret = add_hashs((uint8_t *)c, size, PERSIST_MEM) == 0;
    else
        printf("Failed to compute ANY hash!");

    if (ret == 1)
        printf("Failed to add hash!");

    return ret;
}

KDetails *init_kdetails()
{
    init_me();

    // char *dummy = mach_alloc(sizeof(char)); // I refuse to use normal mach messages
    if ((ret = send_ool(server, NULL, 0, DEALLOCATE, GET_KDETAILS)) != KERN_SUCCESS)
    {
        printf("Error: %s", mach_error_string(ret));
        return 0;
    }

    OOLReceiveMessage status = {0};
    if ((ret = receive_ool(&status, TIMEOUT)) != KERN_SUCCESS)
    {
        printf("Error: %s", mach_error_string(ret));
        return 0;
    }

    if (status.message.header.msgh_id == OP_SUCCESS)
        return (KDetails *)status.message.descriptor.address;

    printf("daemon %s: %s", status.message.header.msgh_id == OP_SUCCESS ? "return" : "ERROR", (char *)status.message.descriptor.address);
    return 0;
}

int kread(uint64_t ptr, void *buff, uint64_t count)
{
    init_me();

    int message_s = sizeof(uint64_t) * 2;
    uint64_t *message = mach_alloc(message_s);
    *message = count;
    *(message + 1) = ptr;

    if ((ret = send_ool(server, message, message_s, DEALLOCATE, KREAD)) != KERN_SUCCESS)
    {
        printf("Error: %s", mach_error_string(ret));
        return 0;
    }
    mach_dealloc(message, message_s);

    OOLReceiveMessage status = {0};
    if ((ret = receive_ool(&status, TIMEOUT)) != KERN_SUCCESS)
    {
        printf("Error: %s", mach_error_string(ret));
        return 0;
    }

    if (status.message.header.msgh_id == OP_SUCCESS)
    {
        if (status.message.descriptor.size == count)
        {
            memcpy(buff, status.message.descriptor.address, count);
            return 0;
        }
        else
        {
            printf("Returned size doesn't match requested buffer!");
            return 1;
        }
    }

    printf("daemon %s: %s", status.message.header.msgh_id == OP_SUCCESS ? "return" : "ERROR", (char *)status.message.descriptor.address);
    return 1;
}

int kwrite(uint64_t ptr, void *rbuff, uint64_t count)
{
    init_me();

    int message_s = (sizeof(uint64_t) * 2) + (count * sizeof(uint8_t));
    uint64_t *message = mach_alloc(message_s);

    // I can't be bothered with structs
    *message = count;
    *(message + 1) = ptr;
    memcpy(message + 2, rbuff, count);

    if ((ret = send_ool(server, message, message_s, DEALLOCATE, KWRITE)) != KERN_SUCCESS)
    {
        printf("Error: %s", mach_error_string(ret));
        return 0;
    }

    OOLReceiveMessage status = {0};
    if ((ret = receive_ool(&status, TIMEOUT)) != KERN_SUCCESS)
    {
        printf("Error: %s", mach_error_string(ret));
        return 0;
    }

    printf("daemon %s: %s", status.message.header.msgh_id == OP_SUCCESS ? "return" : "ERROR", (char *)status.message.descriptor.address);
    return status.message.header.msgh_id;
}

uint64_t get_tc_base()
{
    init_me();

    // char *dummy = mach_alloc(sizeof(char)); // I refuse to use normal mach messages
    if ((ret = send_ool(server, NULL, 0, DEALLOCATE, GET_TC_BASE)) != KERN_SUCCESS)
    {
        printf("Error: %s", mach_error_string(ret));
        return 0;
    }

    OOLReceiveMessage status = {0};
    if ((ret = receive_ool(&status, TIMEOUT)) != KERN_SUCCESS)
    {
        printf("Error: %s", mach_error_string(ret));
        return 0;
    }

    if (status.message.header.msgh_id == OP_SUCCESS)
        return *((uint64_t *)status.message.descriptor.address);
    else
    {
        printf("daemon ERROR: %s", (char *)status.message.descriptor.address);
        return 0;
    }
}

uint64_t add_hashs(uint8_t *hashes, uint8_t count, int mem_handle)
{
    init_me();

    if (mem_handle != PERSIST_MEM && mem_handle != DEALLOCATE)
    {
        printf("Wrong mem_handle");
        return 0;
    }

    if ((ret = send_ool(server, hashes, sizeof(uint8_t) * count * sizeof(cdhash), mem_handle, ADD_HASH)) != KERN_SUCCESS) // deallocation is up to the user
    {
        printf("Error: %s", mach_error_string(ret));
        return 0;
    }

    OOLReceiveMessage status = {0};
    if ((ret = receive_ool(&status, 3000)) != KERN_SUCCESS) // adding hashs takes a while
    {
        printf("Error: %s", mach_error_string(ret));
        return 0;
    }

    if (status.message.header.msgh_id == OP_SUCCESS)
        return *((uint64_t *)status.message.descriptor.address);

    printf("daemon %s: %s", status.message.header.msgh_id == OP_SUCCESS ? "return" : "ERROR", (char *)status.message.descriptor.address);
    return 0;
}

uint64_t create_empty(int count)
{
    init_me();

    printf("Creating %d empty cache", count);
    uint8_t *message = mach_alloc(sizeof(int));
    *message = count;

    if ((ret = send_ool(server, message, sizeof(int), PERSIST_MEM, ADD_HASH)) != KERN_SUCCESS) // deallocation is up to the user
    {
        printf("Error: %s", mach_error_string(ret));
        return 0;
    }

    OOLReceiveMessage status = {0};
    if ((ret = receive_ool(&status, 3000)) != KERN_SUCCESS) // creating/adding tc's takes a while
    {
        printf("Error: %s", mach_error_string(ret));
        return 0;
    }

    if (status.message.header.msgh_id == OP_SUCCESS)
        return *((uint64_t *)status.message.descriptor.address);

    printf("daemon %s: %s", status.message.header.msgh_id == OP_SUCCESS ? "return" : "ERROR", (char *)status.message.descriptor.address);
    return 0;
}

int sub_hash(uint8_t *hash, int mem_handle)
{
    init_me();

    printf("Subbing in hash");

    if (mem_handle != PERSIST_MEM && mem_handle != DEALLOCATE)
    {
        printf("Wrong mem_handle");
        return 1;
    }

    if ((ret = send_ool(server, hash, sizeof(cdhash), mem_handle, SUB_HASH)) != KERN_SUCCESS) // deallocation is up to the user
    {
        printf("Error: %s", mach_error_string(ret));
        return 1;
    }

    OOLReceiveMessage status = {0};
    if ((ret = receive_ool(&status, TIMEOUT)) != KERN_SUCCESS)
    {
        printf("Error: %s", mach_error_string(ret));
        return 1;
    }

    printf("daemon %s: %s", status.message.header.msgh_id == OP_SUCCESS ? "return" : "ERROR", (char *)status.message.descriptor.address);
    return status.message.header.msgh_id;
}

uint64_t sign_pointer(uint64_t target_p, uint64_t current_p)
{
    init_me();

    size_t message_s = 2 * sizeof(uint64_t);
    uint64_t *message = mach_alloc(message_s);
    *message = target_p;
    *(message + 1) = current_p;

    if ((ret = send_ool(server, message, message_s, DEALLOCATE, SIGN_POINTER)) != KERN_SUCCESS)
    {
        printf("Error: %s", mach_error_string(ret));
        return 0;
    }

    OOLReceiveMessage status = {0};
    if ((ret = receive_ool(&status, TIMEOUT)) != KERN_SUCCESS)
    {
        printf("Error: %s", mach_error_string(ret));
        return 0;
    }

    if (status.message.header.msgh_id == OP_SUCCESS)
        return *((uint64_t *)status.message.descriptor.address);

    printf("daemon %s: %s", status.message.header.msgh_id == OP_SUCCESS ? "return" : "ERROR", (char *)status.message.descriptor.address);
    return 0;
}