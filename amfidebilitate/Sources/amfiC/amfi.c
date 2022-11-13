#include "amfi.h"

uint64_t cubbyhole = 0;
char *name = "com.fugu.amfi";

void get_kdetails(OOLReceiveMessage *raw_msg)
{
    char *return_m = mach_alloc(RETURN_SIZE);

    if (!fetch_deets((KDetails *)return_m))
    {
        send_ool(raw_msg->message.header.msgh_remote_port, return_m, RETURN_SIZE, DEALLOCATE, OP_SUCCESS);
        goto success;
    }
    else
        strcpy(return_m, "Failed to get kdetails!");

    printf("error: %s", return_m);
    send_ool(raw_msg->message.header.msgh_remote_port, return_m, RETURN_SIZE, DEALLOCATE, OP_FAIL);

success:
    mach_dealloc(return_m, RETURN_SIZE);
}
void kread(OOLReceiveMessage *raw_msg)
{
    char *error = mach_alloc(RETURN_SIZE);

    if (raw_msg->message.descriptor.size == (sizeof(uint64_t) * 2))
    {
        uint64_t count = *(uint64_t *)raw_msg->message.descriptor.address;
        uint8_t *mem_b = mach_alloc(count);

        if (count > 0)
        {
            uint64_t kptr = *((uint64_t *)raw_msg->message.descriptor.address + 1); // *cough - don't judge, it's beautiful in it's own way
            if (!kread_s(kptr, mem_b, count))
            {
                send_ool(raw_msg->message.header.msgh_remote_port, mem_b, count, DEALLOCATE, OP_SUCCESS);
                mach_dealloc(mem_b, count);
                goto success;
            }
            else
                strcpy(error, "Failed to read memory!");
        }
        else
            strcpy(error, "Read counter can't be zero!");
    }
    else
        strcpy(error, "Malformed kernel read request!");

    printf("error: %s", error);
    send_ool(raw_msg->message.header.msgh_remote_port, error, RETURN_SIZE, DEALLOCATE, OP_FAIL);

success:
    mach_dealloc(error, RETURN_SIZE);
}
void kwrite(OOLReceiveMessage *raw_msg)
{
    char *error = mach_alloc(RETURN_SIZE);

    if (raw_msg->message.descriptor.size > ((sizeof(uint64_t) * 2) + 1)) // there should at least be enough data to constitute counter, address + 1 byte
    {
        uint64_t count = *(uint64_t *)raw_msg->message.descriptor.address;

        if (count > 0)
        {
            uint64_t kptr = *((uint64_t *)raw_msg->message.descriptor.address + 1); // *cough - don't judge, it's beautiful in it's own way
            if (!kwrite_s(kptr, (uint64_t *)raw_msg->message.descriptor.address + 2, count))
            {
                send_ool(raw_msg->message.header.msgh_remote_port, NULL, 0, DEALLOCATE, OP_SUCCESS);
                goto success;
            }
            else
                strcpy(error, "Failed to write to memory!");
        }
        else
            strcpy(error, "Write counter can't be zero!");
    }
    else
        strcpy(error, "Malformed kernel write request!");

    printf("error: %s", error);
    send_ool(raw_msg->message.header.msgh_remote_port, error, RETURN_SIZE, DEALLOCATE, OP_FAIL);

success:
    mach_dealloc(error, RETURN_SIZE);
}

void get_tc_base(OOLReceiveMessage *raw_msg) // make a full fledged struct of useful offsets
{
    if (cubbyhole > 0)
    {
        send_ool(raw_msg->message.header.msgh_remote_port, &cubbyhole, sizeof(cubbyhole), PERSIST_MEM, OP_SUCCESS);
        return;
    }
    else
    {
        char *return_m = mach_alloc(RETURN_SIZE);
        strcpy(return_m, "cubbyhole not made!");
        send_ool(raw_msg->message.header.msgh_remote_port, return_m, RETURN_SIZE, DEALLOCATE, OP_FAIL);
        mach_dealloc(return_m, RETURN_SIZE);
        return;
    }
}

void add_hashs(OOLReceiveMessage *raw_msg)
{
    char *return_m = mach_alloc(RETURN_SIZE);
    if (raw_msg->message.descriptor.size % CDHASH == 0)
    {
        int count = raw_msg->message.descriptor.size / CDHASH;

        if ((*((uint64_t *)return_m) = addHashs(raw_msg->message.descriptor.address, count)) != 0)
        {
            send_ool(raw_msg->message.header.msgh_remote_port, return_m, RETURN_SIZE, DEALLOCATE, OP_SUCCESS);
            goto success;
        }
        else
            strcpy(return_m, "Failed to create trustcache");
    }
    else
        strcpy(return_m, "Buffer not divisible by CDHASH_LENGTH (22 bytes)");

    printf("Error: %s", return_m);
    send_ool(raw_msg->message.header.msgh_remote_port, return_m, RETURN_SIZE, DEALLOCATE, OP_FAIL);

success:
    mach_dealloc(return_m, RETURN_SIZE);
}

void create_empty(OOLReceiveMessage *raw_msg)
{
    int *count = raw_msg->message.descriptor.address;
    char *return_m = mach_alloc(RETURN_SIZE);

    if (*count > 0 && *count < 0xFFFF)
    {
        if ((*((uint64_t *)return_m) = createEmpty(*count)))
        {
            send_ool(raw_msg->message.header.msgh_remote_port, return_m, RETURN_SIZE, DEALLOCATE, OP_SUCCESS);
            goto success;
        }
        else
            strcpy(return_m, "Failed to create empty trustcache!");
    }
    else
        strcpy(return_m, "Trustcache count can't be 0 or be too large!");

    printf("Error: %s", return_m);
    send_ool(raw_msg->message.header.msgh_remote_port, return_m, RETURN_SIZE, DEALLOCATE, OP_FAIL);

success:
    mach_dealloc(return_m, RETURN_SIZE);
}

void sub_hash(OOLReceiveMessage *raw_msg)
{
    char *return_m = mach_alloc(RETURN_SIZE);

    if (subHash(raw_msg->message.descriptor.address))
    {
        strcpy(return_m, "Failed to sub in has");
        printf("ERROR: %s", return_m);
        send_ool(raw_msg->message.header.msgh_remote_port, return_m, RETURN_SIZE, DEALLOCATE, OP_FAIL);
    }
    else
        send_ool(raw_msg->message.header.msgh_remote_port, NULL, 0, DEALLOCATE, OP_SUCCESS);

    mach_dealloc(return_m, RETURN_SIZE);
}

void sign_pointer(OOLReceiveMessage *raw_msg)
{
    uint64_t current = *((uint64_t *)(raw_msg->message.descriptor.address));
    uint64_t target = *((uint64_t *)(raw_msg->message.descriptor.address) + 1);

    char *return_m = mach_alloc(RETURN_SIZE);

    if ((*((uint64_t *)return_m) = signPointer(current, target)))
    {
        send_ool(raw_msg->message.header.msgh_remote_port, return_m, RETURN_SIZE, DEALLOCATE, OP_SUCCESS);
        goto success;
    }
    else
        strcpy(return_m, "Failed to sign pointer!");

    printf("Error: %s", return_m);
    send_ool(raw_msg->message.header.msgh_remote_port, return_m, RETURN_SIZE, DEALLOCATE, OP_FAIL);

success:
    mach_dealloc(return_m, RETURN_SIZE);
}

void amfi_handle(OOLReceiveMessage *raw_msg)
{

    char *error = mach_alloc(RETURN_SIZE);

    if (raw_msg->message.descriptor.size > 0 || raw_msg->message.header.msgh_id == GET_KDETAILS || raw_msg->message.header.msgh_id == GET_TC_BASE) // sorry for hacky solution, these are the functions supporting NULL data
    {
        if (raw_msg->message.header.msgh_remote_port)
        {
            switch (raw_msg->message.header.msgh_id)
            {
            case GET_KDETAILS:
                get_kdetails(raw_msg);
                goto success;
            case KREAD:
                kread(raw_msg);
                goto success;
            case KWRITE:
                kwrite(raw_msg);
                goto success;
            case GET_TC_BASE:
                get_tc_base(raw_msg);
                goto success;
            case CREATE_EMPTY:
                create_empty(raw_msg);
                goto success;
            case SUB_HASH:
                sub_hash(raw_msg);
                goto success;
            case ADD_HASH:
                add_hashs(raw_msg);
                goto success;
            case SIGN_POINTER:
                sign_pointer(raw_msg);
                goto success;
            }

            strcpy(error, "Malformed msgh_id!");
        }
        else
            strcpy(error, "No remote port in message!");
    }
    else
        strcpy(error, "Size cannot be zero!");

    printf("Error: %s", error);
    send_ool(raw_msg->message.header.msgh_remote_port, error, RETURN_SIZE, DEALLOCATE, OP_FAIL);

success:
    mach_dealloc(raw_msg->message.descriptor.address, raw_msg->message.descriptor.size); // you know where there's a dripping sound somewhere but you can't FUCKING find where?! Leaking mem - three hours to find it
    mach_dealloc(error, RETURN_SIZE);
}

int setup_mach()
{
    init_mach();

    if ((ret = bootstrap_register(bootstrap_port, name, receive_port)) != KERN_SUCCESS)
    {
        printf("Failed port allocation!: %s", mach_error_string(ret));
        return 0;
    }

    return 1;
}