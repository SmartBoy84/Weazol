bunch of offsets here - https://github.com/jakeajames/multi_path/blob/b8ff6c07d6c2177c68067cb423f62eb3f1c2a213/multi_path/jailbreakd/offsetof.c

src - https://h3adsh0tzz.com/2020/01/macho-file-format and https://opensource.apple.com/source/xnu/xnu-4570.1.46/EXTERNAL_HEADERS/mach-o/loader.h.auto.html

Important, load command structs are stored atop their data (cmd size includes
8 bytes of the header)

```c
#define MH_MAGIC_64  PREDEFINED; // kbase described start of kernel's Mach-O header - this magic number indicates start of struct of kernel mach-o

#define LC_SEGMENT_64 0x19 /* 64 bit segment */
#define LC_UUID 0x1b       /* the uuid */
```

reading from the allproc offset gives the address to the proc struct of the latest spawned process
it's better to use a while loop (reading backwards along the linked list) to match pids rather than assume that the proc at that pointer is the running process (other processes could have spawned in the time the process was run)
Checkout jakeshack dummy guide/write up on his rootless 'jailbreak'

https://github.com/apple/darwin-xnu/blob/main/security/_label.h#L83
sandbox escaped by nullifying pointer in sandbox slot
Nope, will need to copy over the kernel ucred

Note a lot of the kernel structs are found in sdk and can be imported (e.g., sys/ucred.h)
https://twitter.com/xina520/status/1515720109255393282
