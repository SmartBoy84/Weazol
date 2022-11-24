#include "common.h"

DYLD_INTERPOSE(fake_posix_spawn, posix_spawn);
DYLD_INTERPOSE(fake_posix_spawnp, posix_spawnp);

__attribute__((constructor)) static void ctor(void)
{
	const char *name = "/bob.txt";
	FILE *fptr = fopen(name, "a+");

	fprintf(fptr, "%s: %s\n", get_name(), "dyld: init");
	fflush(fptr);

	fclose(fptr);

	orig_pspawn = posix_spawn;
	orig_pspawnp = posix_spawnp;
}