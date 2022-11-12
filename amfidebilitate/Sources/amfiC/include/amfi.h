#include "machapi.h"

#define CDHASH 22

void amfi_handle(OOLReceiveMessage *raw_msg);
int setup_mach();

// swift portal
extern uint64_t cubbyhole;
extern int kread_s(uint64_t kptr, void *buffer, uint64_t count);
extern int kwrite_s(uint64_t kptr, void *buffer, uint64_t count);
extern int fetch_deets(KDetails *kdeets);
extern uint64_t addHashs(uint8_t *hashs, int count);
extern uint64_t createEmpty(int count);
extern int subHash(uint8_t *hash);
extern uint64_t signPointer(uint64_t value, uint64_t context);