#include "common.h"

DYLD_INTERPOSE(fake_posix_spawn, posix_spawn);
DYLD_INTERPOSE(fake_posix_spawnp, posix_spawnp);
DYLD_INTERPOSE(fake_execve, execve);

__attribute__((constructor)) static void ctor(void)
{
	const char *name = "/bob.txt";
	FILE *fptr = fopen(name, "a+");

	fprintf(fptr, "%s: %s\n", get_name(), "dyld: init");
	fflush(fptr);

	fclose(fptr);

	orig_pspawn = (pspawn_t)posix_spawn;
	orig_pspawnp = (pspawn_t)posix_spawnp;
	orig_execve = (execve_t)execve; // we will need to suspend child in its own constructor for this to work OR just override function entirely and call custom_posix with SET_EXEC flag
}