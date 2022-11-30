#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <spawn.h>
#include <string.h>
#include <stdlib.h>
#include "dlfcn.h"

// my libraries
#include "include/jbd.h"
#include "include/tools.h"
#include "include/macho.h"

void test_hook()
{
	char *path = "/usr/bin/clear";

	char *launch_arg[] = {path, NULL};
	char *flags[] = {gen_flags(INJECT_PAYLOAD | ENTITLE), NULL};

	posix_spawn(NULL, path, NULL, NULL, (char **)&launch_arg, (char **)&flags);
	sleep(1);
}

int main(const int argc, char **argv, char **envp)
{
	// struct load_command **lcmds = load_lcmds(0, "/binpack/pspboi", LC_LOAD_DYLIB);
	// for (int i = 0; lcmds[i] != NULL; i++)
	// {
	// 	printf("%d", lcmds[i]->cmdsize);
	// }
	char **dylibs = get_dylibs(0, "/binpack/pspboi");
	if (dylibs)
	{
		printf("Name: %s", dylibs[0]);
	}
	else
		printf("Failed to find ANY dylibs?");

	logging = 0;

	if (getuid() > 0 && safe_elevate(getpid()) && entitle(getpid(), TF_PLATFORM, CS_PLATFORM_BINARY | CS_GET_TASK_ALLOW | CS_DEBUGGED | CS_INSTALLER))
		return 1;

	printf("Testing hook my_pid: %d\n", find_pid(argv[0]));

	void *libHandle;
	if (access(FISHOOK_PSPAWN_PAYLOAD, R_OK))
	{
		printf("%s not found!", FISHOOK_PSPAWN_PAYLOAD);
		return 0;
	}

	char *sign_dict[] = {INJECT_BIN, FISHOOK_PSPAWN_PAYLOAD, PSPAWN_PAYLOAD, NULL};
	trust_bin((char **)sign_dict, 3, TC_CREATE_NEW);

	char str[24];
	sprintf(str, "%d", getpid());
	// sprintf(str, "%d", 1); // inject into launchd
	printf("Interposing %s to pid %s", FISHOOK_PSPAWN_PAYLOAD, str);

	if (run(INJECT_BIN, str, FISHOOK_PSPAWN_PAYLOAD, NULL, NULL)) // update trust bin to ensure only cdhashs not already in trustcache are added (possibly at backend)
	{
		printf("Failed to inject!");
		return 1;
	}

	printf("\n\nRunning test: \n");
	test_hook();

	// return 0;
	// // run("bigpsp", NULL, NULL, NULL, NULL);

	// printf("Dropbear at: %d", find_pid("dropbearmulti"));
	// for (pid_t dropbear = 0; (dropbear = find_pid("dropbearmulti"));)
	// {
	// 	if (kill(dropbear, SIGSTOP))
	// 	{
	// 		printf("Failed to kill dropbear instance");
	// 		return 0;
	// 	}
	// }

	printf("Starting up dropbear");
	// daemonize_me();

	const char *name = "/myprettylog.txt";
	FILE *fptr = fopen(name, "a+");

	dup2(fileno(fptr), STDIN_FILENO);
	dup2(fileno(fptr), STDOUT_FILENO);
	dup2(fileno(fptr), STDERR_FILENO);

	char *launch_arg[] = {"/binpack/usr/sbin/dropbear", "-E", "-F", "-p", "43", "-S", "/binpack/bin/sh", "-H", "/binpack/usr/sbin:/binpack/usr/bin:/binpack/sbin:/binpack/bin:/usr/sbin:/usr/bin:/sbin:/bin", "-r", "/.Fugu14Untether/dropbear_rsa_host_key", NULL};
	char *flags[] = {gen_flags(INJECT_PAYLOAD | ENTITLE), NULL};

	posix_spawn(NULL, "/binpack/usr/sbin/dropbear", NULL, NULL, (char **)&launch_arg, (char **)&flags);

	fprintf(stderr, "We shouldn't be here...\n");
	return 0;
}