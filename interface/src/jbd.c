#include "include/jbd.h"
#include "include/tools.h"
#include "include/cdhash.h"
#include "include/kernel.h"
#include "headers/shenanigans.h"

mach_port_t server = 0;
int logging = 1;

int init_me()
{
    if (init_mach())
        return 1;

    if (server == 0)
    {
        if (bootstrap_look_up(server, server_name, &server) == MACH_MSG_SUCCESS) // always done on a mach op to ensure amfidebilitate is running
            return 0;
        else
        {
            printf("Failed to get server port - HOW?! Hang on, I'll try to start it...");
            run(launchctl, "load", amfiplist, NULL, NULL); // super unsafe - what if the user deletes the plist? I don't care

            printf("Waiting for daemon to wake."); // honestly prefer just being patient over bombaring boostrap serer with XPC messages
            for (int i = 0; i < 10; i++)           // should take no longer than this
            {
                printf(".");
                sleep(1);

                if (bootstrap_look_up(server, server_name, &server) == MACH_MSG_SUCCESS)
                {
                    sleep(3); // wait a bit for the daemon to properly wake
                    return 0;
                }
            }
            return 1;
        }
    }
    return 0;
}

int trust_bin(char **path, int path_n, int sub)
{
    int ret = 0;

    cdhash_list *cdhash_master = malloc(sizeof(cdhash_list) * path_n);
    int count = 0; // number of valid cdhashes
    int size = 0;  // each cdhash struct can contain multiple hashes

    KDetails *kdeets = init_kdetails();
    addr64_t tc_start = read_pointer(kdeets->tcroot);

    kern_tc *tc = malloc(sizeof(kern_tc));

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
        addr64_t tc_ptr = tc_start;
        size_t found_hash_size = sizeof(cdhash) * ret_count;

        while (!kread(tc_ptr, tc, sizeof(kern_tc)))
        {
            if (tc->header.size < ret_count)
                continue;

            tc_ptr += sizeof(kern_tc);

            size_t tc_hash_size = sizeof(cdhash) * tc->header.size;
            cdhash *hash = malloc(tc_hash_size);

            if (!kread(tc_ptr, hash, tc_hash_size))
            {
                if (memmem(hash, tc_hash_size, c, found_hash_size) != NULL)
                {
                    free(hash);
                    goto found;
                }
            }

            free(hash);
            tc_ptr = read_pointer((addr64_t)tc->next);
        }

        cdhash_master[i].count = ret_count;
        cdhash_master[i].hash = c;

        count++;
        size += ret_count;
        continue; // don't free() since the hash pointer will be stored in the buffer

    found: // we come here when it's hash is found to be already in custom trustcache
        free(c);
    }

    if (count == 0)
    {
        ret = 1;
        goto end;
    }

    cdhash *c = malloc(sizeof(cdhash) * size);
    cdhash *c_ptr = c;

    for (int i = 0; i < count; i++)
    {
        if (cdhash_master[i].count > 0)
        {
            memcpy(c_ptr, cdhash_master[i].hash, sizeof(cdhash) * cdhash_master[i].count);
            free(cdhash_master[i].hash);
            c_ptr += cdhash_master[i].count;
        }
    }

    // for (int x = 0; x < size; x++)
    // {
    //     for (int i = 0; i < sizeof(cdhash); i++)
    //     {
    //         printf("%d ", *((uint8_t *)(c + x) + i));
    //     }
    //     printf("\n");
    // }

    if (size == 1 && sub)
        ret = sub_hash((uint8_t *)c, PERSIST_MEM);
    else // no need for further size check, that's done before
        ret = add_hashs((uint8_t *)c, size, PERSIST_MEM) == 0;

    free(c);

    if (ret == 1)
    {
        ret = 1;
        printf("Failed to add hash!");
    }

    goto end;

end:
    free(tc);
    // free(hash);

    return ret;
}

KDetails *init_kdetails()
{
    if (init_me())
        return 0;

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
    else if (logging)
        printf("daemon ERROR: %s", (char *)status.message.descriptor.address);

    return 0;
}

int kread(uint64_t ptr, void *buff, uint64_t count)
{
    if (init_me())
        return 1;

    int message_s = sizeof(uint64_t) * 2;
    uint64_t *message = mach_alloc(message_s);
    *message = count;
    *(message + 1) = ptr;

    if ((ret = send_ool(server, message, message_s, DEALLOCATE, KREAD)) != KERN_SUCCESS)
    {
        printf("Error: %s", mach_error_string(ret));
        return 1;
    }
    mach_dealloc(message, message_s);

    OOLReceiveMessage status = {0};
    if ((ret = receive_ool(&status, TIMEOUT)) != KERN_SUCCESS)
    {
        printf("Error: %s", mach_error_string(ret));
        return 1;
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
    else if (logging)
        printf("daemon ERROR: %s", (char *)status.message.descriptor.address);

    return 1;
}

int kwrite(uint64_t ptr, void *rbuff, uint64_t count)
{
    if (init_me())
        return 1;

    int message_s = (sizeof(uint64_t) * 2) + (count * sizeof(uint8_t));
    uint64_t *message = mach_alloc(message_s);

    // I can't be bothered with structs
    *message = count;
    *(message + 1) = ptr;
    memcpy(message + 2, rbuff, count);

    if ((ret = send_ool(server, message, message_s, DEALLOCATE, KWRITE)) != KERN_SUCCESS)
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

    if (status.message.header.msgh_id != OP_SUCCESS && logging)
        printf("daemon ERROR: %s", (char *)status.message.descriptor.address);

    return status.message.header.msgh_id;
}

uint64_t get_tc_base()
{
    if (init_me())
        return 0;

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
    if (init_me())
        return 0;

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
    else
        printf("daemon ERROR: %s", (char *)status.message.descriptor.address);

    return 0;
}

uint64_t create_empty(int count)
{
    if (init_me())
        return 0;

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
    else
        printf("daemon ERROR: %s", (char *)status.message.descriptor.address);

    return 0;
}

int sub_hash(uint8_t *hash, int mem_handle)
{
    if (init_me())
        return 1;

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

    if (status.message.header.msgh_id != OP_SUCCESS)
        printf("daemon ERROR: %s", (char *)status.message.descriptor.address);

    return status.message.header.msgh_id;
}

uint64_t sign_pointer(uint64_t target_p, uint64_t current_p)
{
    if (init_me())
        return 0;

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
    else
        printf("daemon ERROR: %s", (char *)status.message.descriptor.address);

    return 0;
}
