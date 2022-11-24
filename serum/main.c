#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <spawn.h>
#include <string.h>
#include <stdlib.h>

#include "include/jbd.h"
#include "include/tools.h"

void test_hook()
{
	run("/bin/tar", NULL, NULL, NULL, NULL);
	sleep(1);
}

int main(const int argc, char **argv, char **envp)
{
	for (char **env = envp; *env != 0; env++)
	{
		char *thisEnv = *env;
		printf("%s\n", thisEnv);
	}

	if (getuid() > 0 && safe_elevate(getpid()))
		return 1;

	if (entitle(getpid(), TF_PLATFORM, CS_PLATFORM_BINARY | CS_GET_TASK_ALLOW | CS_DEBUGGED))
	{
		printf("Failed to entitle myself");
		return 1;
	}

	printf("Testing hook my_pid: %d\n", find_pid(argv[0]));

	void *libHandle;
	if (access(PSPAWN_PAYLOAD, R_OK))
	{
		printf("%s not found!", PSPAWN_PAYLOAD);
		return 0;
	}

	char *sign_dict[] = {PSPAWN_PAYLOAD, INJECT_BIN};
	if (trust_bin((char **)&sign_dict, 2))
	{
		printf("Failed to trust files!"); // payload may be signed but this ensures daemon is active (check jbd.c/init_me())
		return 0;
	}

	char str[24];
	sprintf(str, "%d", getpid());
	// sprintf(str, "%d", 1); // inject into launchd
	printf("Interposing %s to pid %s", PSPAWN_PAYLOAD, str);

	if (run(INJECT_BIN, str, PSPAWN_PAYLOAD, NULL, NULL))
	{
		printf("Failed to inject!");
		return 1;
	}

	// run("bigpsp", NULL, NULL, NULL, NULL);

	// for (;;)
	// 	test_hook();

	return 0;
}