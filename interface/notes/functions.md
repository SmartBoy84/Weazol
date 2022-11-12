int print_my_entitlements()
{

    // typedef struct
    // {
    //     uint64_t self_addr;
    //     uint64_t items_addr;
    //     uint32_t count;
    //     uint32_t cap;
    //     char **names;
    //     kDictEntry *items;
    //     char data[0];
    // } kOSDict;

    // http://newosxbook.com/QiLin/qilin.pdf
    //  tq-pre-jailbreak

    addr64_t our_ucred = read_pointer(toolbox, toolbox->offsets->my_proc + __ucred_offset);
    addr64_t cr_label = read_pointer(toolbox, our_ucred + __cr_label_offset);
    addr64_t macf_slot = read_pointer(toolbox, cr_label + __amfi_slot_offset);

    char *obj = malloc(0x28);
    toolbox->kread(macf_slot, obj, 0x28);

    uint32_t cap = *(uint32_t *)(obj + 0x18);
    printf("%d is cap", ((kOSDict *)obj)->cap);

    kOSDict *dict;
    size_t alloc_size = sizeof(*dict) + cap * (sizeof(kDictEntry) + sizeof(char *) + 256);
    dict = (kOSDict *)malloc(alloc_size);

    dict->self_addr = macf_slot;
    dict->items_addr = read_pointer(toolbox, macf_slot + 0x20);
    dict->count = *(uint32_t *)(obj + 0x14);
    dict->cap = cap;

    char *ptr = dict->data;
    dict->items = (kDictEntry *)ptr;
    ptr += sizeof(kDictEntry) * dict->cap;
    dict->names = (char **)ptr;
    ptr += sizeof(char *) * dict->cap;
    for (int i = 0; i < dict->cap; i++)
    {
        dict->names[i] = ptr;
        ptr += 256;
    }
    printf("dict %#llx, items %#llx, count %u, capacity %u",
           dict->self_addr, dict->items_addr, dict->count, dict->cap);
    alloc_size = sizeof(kDictEntry) * dict->cap;
    toolbox->kread(dict->items_addr, dict->items, alloc_size);
    for (int i = 0; i < dict->count; i++)
    {
        char obj[0x18];
        toolbox->kread(dict->items[i].key, obj, sizeof(obj));
        // OSSymbol
        uint32_t len = *(uint32_t *)(obj + 0xc) >> 14;
        if (len >= 256)
        {
            len = 255;
        }
        // PACed in iOS 14.3
        uint64_t string = *(uint64_t *)(obj + 0x10);
        string |= 0xffffff8000000000;
        toolbox->kread(string, dict->names[i], len);
        dict->names[i][len] = 0;
        printf("    -> %s", dict->names[i]);
    }
}
