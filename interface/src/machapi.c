#include <stdio.h>
#include "include/machapi.h"

/*
mach_msg(
    msg,
    option,
    send_size,
    recv_size,
    recv_name
    timeout,
    notify_port
)
*/

OOLMessage message = {0}; // yeah, I'm lazy
mach_port_t receive_port = 0;
kern_return_t ret;

mach_msg_return_t receive_ool(OOLReceiveMessage *rcvMessage, mach_msg_timeout_t timeout)
{
    mach_msg_return_t ret = mach_msg(
        (mach_msg_header_t *)rcvMessage,
        timeout == 0 ? MACH_RCV_MSG : MACH_RCV_MSG | MACH_RCV_TIMEOUT,
        0,
        sizeof(*rcvMessage),
        receive_port,
        timeout,
        MACH_PORT_NULL);

    if (ret != MACH_MSG_SUCCESS)
        return ret;

    return MACH_MSG_SUCCESS;
}

kern_return_t ret;

int init_mach()
{
    if (receive_port == 0)
    {
        if (
            (ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &receive_port)) != KERN_SUCCESS ||
            (ret = mach_port_insert_right(mach_task_self(), receive_port, receive_port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS))
        {
            printf("Port allocation failed: %s", mach_error_string(ret));
            return 1;
        }
    }

    if (message.msgh_descriptor_count == 0)
    {
        message.header.msgh_bits = MACH_MSGH_BITS_SET(
            MACH_MSG_TYPE_COPY_SEND, // remote
            MACH_MSG_TYPE_MAKE_SEND, // local
            0,                       // voucher
            MACH_MSGH_BITS_COMPLEX   // other - indicates kernel involvement in data exchange (not required for simple mach messages)
        );
        message.header.msgh_size = sizeof(message);
        message.header.msgh_local_port = receive_port;

        message.descriptor.copy = MACH_MSG_VIRTUAL_COPY; // CoW (copy on write), efficient way of copying - kernel simply remaps address spaces allowing for the "memory" to be shared
        // however if deallocate is set to false, then a copy of the memory space is created when it is written to by the client

        message.descriptor.type = MACH_MSG_OOL_DESCRIPTOR; // since kernel does some processing, must indicate that this is an OOL complex message
        message.msgh_descriptor_count = 1;
    }

    return 0;
}

void *mach_alloc(size_t count) // stock malloc doesn't work with DEALLOCATE (program freezes)
{
    void *oolBuffer = NULL;
    if (vm_allocate(
            mach_task_self(),
            (vm_address_t *)&oolBuffer,
            count,
            VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS)
    {
        printf("Failed to allocate memory buffer\n");
        return NULL;
    }
    return oolBuffer;
}

void mach_dealloc(void *buf, size_t size)
{
    if ((ret = vm_deallocate(mach_task_self(), (vm_address_t)buf, (vm_size_t)size) != KERN_SUCCESS))
    {
        printf("Deallocation failed: %s", mach_error_string(ret));
    }
}

mach_msg_return_t send_ool(
    mach_port_name_t port,
    void *addr,
    mach_msg_size_t size,
    int deallocate, mach_msg_id_t id)
{
    init_mach();

    message.header.msgh_remote_port = port;
    message.header.msgh_id = id; // ID for server's sake (unused)

    message.descriptor.size = size;
    message.descriptor.address = addr; // memory address

    message.descriptor.deallocate = deallocate; // indicates whether to deallocate the memory region from this process's address space

    return mach_msg(
        (mach_msg_header_t *)&message,
        MACH_SEND_MSG,
        sizeof(message),
        0,
        MACH_PORT_NULL,
        MACH_MSG_TIMEOUT_NONE,
        MACH_PORT_NULL);
}

void destroy_exit(int error)
{
    mach_port_destroy(mach_task_self(), receive_port);
    exit(error);
}