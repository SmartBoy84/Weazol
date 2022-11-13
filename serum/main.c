#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <spawn.h>
#include <string.h>
#include <stdlib.h>
#include "include/jbd.h"
#include "include/kernel.h"

#define cynject "/usr/bin/cynject"
#define pspawn_payload "/binpack/pspawn.dylib"

int main(const int argc, char **argv)
{
	if (getuid() > 0 && safe_elevate(getpid()))
		return 1;

	printf("Testing hook my_pid: %d\n", find_pid(argv[0]));

	void *libHandle;
	if (access(pspawn_payload, R_OK))
	{
		printf("%s not found!", pspawn_payload);
		return 0;
	}

	char *sign_dict[] = {pspawn_payload};
	if (trust_bin(&sign_dict, 1))
	{
		printf("Failed to trust files!"); // payload may be signed but this ensures daemon is active (check jbd.c/init_me())
		return 0;
	}

	const char *name = "/bob.txt";
	FILE *fptr = fopen(name, "a+");

	fprintf(fptr, "HELLO FROM MAIN.C!");

	printf("Interposing %s to pid %d", pspawn_payload, getpid());

	char str[24];
	sprintf(str, "%d", getpid());
	run(cynject, str, pspawn_payload, NULL);

	run("/bin/echo", "HELLO WORLD!", NULL, NULL);
	return 0;
}