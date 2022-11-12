#ifndef BLANKET__AMFID__CDHASH_H_
#define BLANKET__AMFID__CDHASH_H_

#include <stdbool.h>
#include <stdlib.h>
#include "headers/cs_blobs.h"
#include "machapi.h"

typedef struct
{
	uint8_t cdhash[20];
	uint8_t hash_type;
	uint8_t flag;
} cdhash;

typedef struct
{
	int count;
	cdhash *hash;

} cdhash_list;

int find_cdhash(const char *path, size_t size, cdhash **h);

#endif