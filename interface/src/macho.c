#include "macho.h"
#include "jbd.h"
#include "kernel.h"

#include <libkern/OSAtomic.h>

int macho_read(FILE *fptr, pid_t pid, uint64_t address, void *buffer, size_t length)
{
    int ret = 1;
    if (pid)
        printf("Still under construction!");
    else if (fptr)
    {
        fseek(fptr, address, SEEK_SET);
        ret = fread(buffer, length, 1, fptr) ? 0 : 1;
    }
    else
        printf("No pid or fptr!");

    if (ret)
        printf("Failed to read");

    return ret;
}

struct mach_header_64 *get_header(pid_t pid, char *path)
{
    struct mach_header_64 *header = malloc(sizeof(struct mach_header_64));

    FILE *fptr = NULL;
    int ret = 1;

    if (path && strlen(path) > 0)
    {
        fptr = fopen(path, "rb");
        if (!fptr)
        {
            printf("Failed to find %s", path);
            goto done;
        }
    }

    uint32_t magic = 0;
    if (!macho_read(fptr, pid, 0, &magic, sizeof(uint32_t)))
    {
        if (magic != MH_MAGIC_64) // don't bother with 32bit mach-o
            printf("File is not a 64bit macho-o executable!");
        else
        {
            if (!macho_read(fptr, pid, 0, header, sizeof(struct mach_header_64)))
                ret = 0;
        }
    }

done:
    if (fptr)
        fclose(fptr);

    if (ret)
    {
        free(header);
        header = NULL;
    }

    return header;
}

struct load_command **load_lcmds(pid_t pid, char *path, int mode)
{
    struct load_command **search_lcmd = NULL;
    size_t size = 0;

    FILE *fptr = NULL;
    int ret = 1;

    struct mach_header_64 *bin = get_header(pid, path);
    if (bin)
    {
        if (path && strlen(path) > 0)
        {
            fptr = fopen(path, "rb");
            if (!fptr)
            {
                printf("Failed to find %s", path);
                goto done;
            }
        }

        struct load_command *lc_test = malloc(sizeof(struct load_command));
        addr64_t cur = sizeof(struct mach_header_64);

        for (int i = 0; i < bin->ncmds; i++)
        {
            if (!macho_read(fptr, pid, cur, lc_test, sizeof(struct load_command)))
            {
                if (lc_test->cmd == mode)
                {
                    search_lcmd = realloc(search_lcmd, size + 1);
                    search_lcmd[size] = malloc(lc_test->cmdsize);

                    if (macho_read(fptr, pid, cur, search_lcmd[size], lc_test->cmdsize))
                    {
                        printf("[WARNING] failed to read load command");
                        free(search_lcmd[size]);
                        search_lcmd = realloc(search_lcmd, size); // change it back to its old size
                    }
                    else
                        size++;
                }
            }
            else
                printf("[WARNING] failed to read load command");

            cur += lc_test->cmdsize;
        }
        free(lc_test);

        if (size > 0)
        {
            search_lcmd = realloc(search_lcmd, size + 1);
            search_lcmd[size] = NULL; // like a usual array of strings

            ret = 0; // success!
        }
    }

done:
    if (fptr)
        fclose(fptr);

    if (ret)
    {
        if (search_lcmd)
        {
            for (struct load_command *i = search_lcmd[0]; i != NULL; i++)
                free(i);
            free(search_lcmd);

            search_lcmd = NULL;
        }
    }

    return search_lcmd;
}

char **get_dylibs(pid_t pid, char *path)
{
    char **dylibs = NULL;
    size_t size = 0;

    int ret = 1;
    FILE *fptr = NULL;

    // types from https://opensource.apple.com/source/xnu/xnu-4570.41.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html
    struct load_command **search_lcmds_list[] = {
        load_lcmds(pid, path, LC_LOAD_DYLIB),
        load_lcmds(pid, path, LC_REEXPORT_DYLIB),
        load_lcmds(pid, path, LC_LOAD_WEAK_DYLIB),
        load_lcmds(pid, path, LC_ID_DYLIB),
        NULL};

    struct load_command **search_lcmds;
    for (int x = 0; search_lcmds_list[x] != NULL; x++)
    {
        search_lcmds = search_lcmds_list[x];

        if (search_lcmds)
        {
            for (int i = 0; search_lcmds[i] != NULL; i++)
            {
                struct dylib_command *dylib_seg = (struct dylib_command *)search_lcmds[i];

                if (dylib_seg->cmdsize > sizeof(struct dylib_command))
                { // strings in load_commands are found immediately after struct so it's length must be greater if string is present
                    size++;

                    dylibs = realloc(dylibs, size * sizeof(char *));
                    dylibs[size - 1] = malloc(dylib_seg->cmdsize - dylib_seg->dylib.name.offset); // once again, constants can be used here but this looks cooler

                    strcpy(dylibs[size - 1], (char *)dylib_seg + dylib_seg->dylib.name.offset);
                }
                else
                    printf("[WARNING] malformed dylib load_command");
            }

            if (size > 0)
            {
                ret = 0;
                size++;
                dylibs = realloc(dylibs, size * sizeof(char *));
                dylibs[size - 1] = NULL; // as usual with string arrays, cap off with NULL pointer
            }
        }
    }

done:
    // free(search_lcmds);

    if (ret)
    {
        if (dylibs)
        {
            // for (struct load_command *i = search_lcmds[0]; i != NULL; i++)
            //     free(i);
            // free(search_lcmds);

            for (char *i = dylibs[0]; i != NULL; i++)
                free(i);
            free(dylibs);

            dylibs = NULL;
        }
    }

    return dylibs;
}
