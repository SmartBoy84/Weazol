#include "common.h"
#include "fishhook.h"

void *rebind_pspawns()
{
	struct rebinding rebinds[] = {
		{"posix_spawn", (void *)fake_posix_spawn, (void **)&orig_pspawn},
		{"posix_spawnp", (void *)fake_posix_spawnp, (void **)&orig_pspawnp},
		{"execve", (void *)fake_execve, (void **)orig_execve}};
	rebind_symbols(rebinds, 3);

	return NULL;
}

__attribute__((constructor)) static void ctor(void)
{
	const char *name = "/bob.txt";
	FILE *fptr = fopen(name, "a+");

	fprintf(fptr, "%s: %s\n", get_name(), "fishook: init");
	fflush(fptr);

	fclose(fptr);

	if (getpid() == 1) // so we don't slow down launchd
	{
		pthread_t thd;
		pthread_create(&thd, NULL, rebind_pspawns, NULL);
	}
	else
		rebind_pspawns();
}