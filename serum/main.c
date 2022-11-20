#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <spawn.h>
#include <string.h>
#include <stdlib.h>

#include "include/jbd.h"
#include "include/tools.h"

#define cynject "/binpack/opainject"
#define pspawn_payload "/binpack/pspawn.dylib"

void test_hook()
{
	run("/bin/echo", "NOT HOOKED", NULL, NULL);
	sleep(1);
}

int main(const int argc, char **argv)
{
	if (getuid() > 0 && safe_elevate(getpid()))
		return 1;

	// pacify(1, getpid());
	// return 1;

	if (entitle(getpid(), TF_PLATFORM, CS_PLATFORM_BINARY | CS_GET_TASK_ALLOW | CS_DEBUGGED))
	{
		printf("Failed to entitle myself");
		return 1;
	}

	printf("Testing hook my_pid: %d\n", find_pid(argv[0]));

	void *libHandle;
	if (access(pspawn_payload, R_OK))
	{
		printf("%s not found!", pspawn_payload);
		return 0;
	}

	char *sign_dict[] = {pspawn_payload, cynject};
	if (trust_bin(&sign_dict, 2))
	{
		printf("Failed to trust files!"); // payload may be signed but this ensures daemon is active (check jbd.c/init_me())
		return 0;
	}

	printf("Interposing %s to pid %d", pspawn_payload, getpid());

	char str[24];
	sprintf(str, "%d", getpid());
	if (run(cynject, str, pspawn_payload, NULL))
	{
		printf("Failed to inject!");
		return 1;
	}

	for (;;)
		test_hook();

	// run("/bin/echo", "HELLO WORLD!", NULL, NULL);
	return 0;
}