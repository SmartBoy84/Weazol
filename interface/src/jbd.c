#include "include/jbd.h"
#include "include/tools.h"
#include "include/cdhash.h"
#include "include/kernel.h"

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

uint64_t create_empty(int count)
{
    if (init_me())
        return 0;

    uint8_t *message = mach_alloc(sizeof(int));
    *message = count;

    if ((ret = send_ool(server, message, sizeof(int), PERSIST_MEM, CREATE_EMPTY)) != KERN_SUCCESS) // deallocation is up to the user
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