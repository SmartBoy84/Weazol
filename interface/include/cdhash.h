#ifndef BLANKET__AMFID__CDHASH_H_
#define BLANKET__AMFID__CDHASH_H_

#include <stdbool.h>
#include <stdlib.h>
#include "headers/cs_blobs.h"
#include "machapi.h"

// https://github.com/darlinghq/darling-newlkm/blob/15b295e29ec2dad8839e4d3538ef94672cc4b15c/osfmk/vm/pmap.h#L780
// https://github.com/darlinghq/darling-newlkm/blob/master/osfmk/vm/pmap.h
#pragma pack(1)
typedef struct
{
	uint8_t hash[20];
	uint8_t hash_type;
	uint8_t flag;
} cdhash;

typedef struct
{
	uint64_t next;
	uint64_t mod; // current?

	uint32_t version;
	char uuid[16];
	uint32_t count;
} cdhash_header;

typedef struct
{
	cdhash_header header;
	cdhash cdhash;
} cdhash_entry;

#pragma pack(0)

typedef struct
{
	int count;
	cdhash *cdhash;

} cdhash_list;

int find_cdhash(const char *path, size_t size, cdhash **h);

#endif