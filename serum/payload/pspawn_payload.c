#include <stdio.h>
#include <spawn.h>
#include "fishhook.h"
#include "include/jbd.h"
#include <string.h>
#include <pthread.h>

// testing
#include "include/machapi.h"

#define GENERAL_LOG_PATH "/tmp/pspawn_payload_general.log"
#define LAUNCHD_LOG_PATH "/tmp/pspawn_payload_launchd.log"
#define INJECT "/binpack/trust"

typedef int (*pspawn_t)(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *const *argv, char *const *envp);

// #include <dlfcn.h>
// typedef void *(*dlopen_t)(const char *filename, int flags);
// dlopen_t orig_dlopen;
// void *fake_dlopen(const char *filename, int flags, dlopen_t origfunc)
// {
// 	printf("Hooked dlopen");
// 	trust_bin(&filename, 1);
// 	return origfunc(filename, flags);
// }

pspawn_t orig_pspawn, orig_pspawnp;
int status = 0;
int current_process = 0;
char *inject[];

int fake_posix_spawn_common(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *const argv[], char *const envp[], pspawn_t origfunc)
{
	/*
	plan is to hook dlopen() along with this + other functions that reuqire this
	some function to test whether it's in trustcache
	*/

	const char *name = "/bob.txt";
	FILE *fptr = fopen(name, "a+");

	fprintf(fptr, "%s: %s\n", getpid() == 0 ? "LAUNCHD" : "NOT LAUNCHD", path);
	fflush(fptr);

	fclose(fptr);

	status = posix_custom(pid, path, file_actions, attrp, argv, envp, origfunc, 0); // this function handles everything for us
	if (status == 85)																// (error for untrusted binary)
	{
		printf("[PSPAWN] %s not trusted?\n", path);
		run(INJECT, path, NULL, NULL, origfunc);
		return posix_custom(pid, path, file_actions, attrp, argv, envp, origfunc, 0); // not our fault anymore
	}
	else
	{
		printf("[PSPAWN] %s trusted\n", path);
		return status;
	}
}

int fake_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *const argv[], char *const envp[])
{
	return fake_posix_spawn_common(pid, path, file_actions, attrp, argv, envp, orig_pspawn);
}

int fake_posix_spawnp(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *const argv[], char *const envp[])
{
	return fake_posix_spawn_common(pid, path, file_actions, attrp, argv, envp, orig_pspawnp);
}

void rebind_pspawns()
{
	struct rebinding rebinds[] = {
		{"posix_spawn", (void *)fake_posix_spawn, (void **)&orig_pspawn},
		{"posix_spawnp", (void *)fake_posix_spawnp, (void **)&orig_pspawnp}};
	rebind_symbols(rebinds, 2);
}

__attribute__((constructor)) static void ctor(void)
{
	if (getpid() == 1) // so we don't slow down launchd
	{
		pthread_t thd;
		pthread_create(&thd, NULL, rebind_pspawns, NULL);
	}
	else
		rebind_pspawns();
}
