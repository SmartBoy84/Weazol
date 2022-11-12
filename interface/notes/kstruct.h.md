```c
#ifndef KERN_H
#define KERN_H

// src - https://h3adsh0tzz.com/2020/01/macho-file-format
// Important, load command structs are stored atop their data (cmd size includes 8 bytes of the header)

#include <stdint.h>

// struct of the kernel's machO header
typedef struct
{
    uint32_t magic;      // mach magic number
    uint32_t cputype;    // cpu specifier
    uint32_t cpusubtype; // cpu subtype specifier
    uint32_t filetype;   // type of mach-o e.g. exec, dylib ...
    uint32_t ncmds;      // number of load commands
    uint32_t sizeofcmds; // size of load command region
    uint32_t flags;      // flags
    uint32_t reserved;   // *64-bit only* reserved
} mach_header;

// Mach-O structs

/* load command type of segment 64, other at
/ https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h */
#define LC_SEGMENT_64 0x19 /* 64 bit segment */
#define LC_UUID 0x1b       /* the uuid */

// segment 64 load command data
typedef struct
{
    uint32_t cmd;      /* LC_SEGMENT_64 */
    uint32_t cmdsize;  /* includes sizeof section_64 structs */
    char segname[16];  /* segment name */
    uint64_t vmaddr;   /* memory address of this segment */
    uint64_t vmsize;   /* memory size of this segment */
    uint64_t fileoff;  /* file offset of this segment */
    uint64_t filesize; /* amount to map from the file */
    uint32_t maxprot;  /* maximum VM protection */
    uint32_t initprot; /* initial VM protection */
    uint32_t nsects;   /* number of sections in segment */
    uint32_t flags;    /* flags */
} s64cmd;

// uuid command
struct uuid_command {
    uint32_t	cmd;		/* LC_UUID */
    uint32_t	cmdsize;	/* sizeof(struct uuid_command) */
    uint8_t	uuid[16];	/* the 128-bit uuid */
};

// section 64 structures
typedef struct
{
    char sectname[16];  /* name of this section */
    char segname[16];   /* segment this section goes in */
    uint64_t addr;      /* memory address of this section */
    uint64_t size;      /* size in bytes of this section */
    uint32_t offset;    /* file offset of this section */
    uint32_t align;     /* section alignment (power of 2) */
    uint32_t reloff;    /* file offset of relocation entries */
    uint32_t nreloc;    /* number of relocation entries */
    uint32_t flags;     /* flags (section type and attributes)*/
    uint32_t reserved1; /* reserved (for offset or index) */
    uint32_t reserved2; /* reserved (for count or sizeof) */
    uint32_t reserved3; /* reserved */
} s64;

typedef struct
{
    uint32_t cmd;     // type of load command
    uint32_t cmdsize; // size of load command
} lcmd;

#endif
```