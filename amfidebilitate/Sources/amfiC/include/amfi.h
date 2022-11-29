#include "machapi.h"

#define CDHASH 22

void amfi_handle(OOLReceiveMessage *raw_msg);
int setup_mach();

// swift portal
extern int kread_s(uint64_t kptr, void *buffer, uint64_t count);
extern int kwrite_s(uint64_t kptr, void *buffer, uint64_t count);
extern int fetch_deets(KDetails *kdeets);
extern uint64_t init_tc(int count);
extern uint64_t signPointer(uint64_t value, uint64_t context);