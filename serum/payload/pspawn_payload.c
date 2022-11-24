#include <stdio.h>
#include <spawn.h>
#include "fishhook.h"
#include "include/tools.h"
#include "include/kernel.h"
#include <string.h>
#include <pthread.h>
#include <unistd.h>

// testing
#include "include/machapi.h"

pspawn_t orig_pspawn, orig_pspawnp;

char *get_name()
{
	char pathbuf[PROC_PIDPATHINFO_MAXSIZE] = {0};
	char *error = "Failed";
	return proc_pidpath(getpid(), pathbuf, sizeof(pathbuf)) > 0 ? pathbuf : error;
}

// void *fake_dlopen(const char *filename, int flags, dlopen_t origfunc)
// there's an entitlement for this, check electra

int status = 0;
int current_process = 0;

static int fake_posix_spawn_common(pid_t *restrict pid, const char *restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict], pspawn_t origfunc)
{
	const char *name = "/bob.txt";
	FILE *fptr = fopen(name, "a+");

	fprintf(fptr, "%s: %s\n", get_name(), path);
	fflush(fptr);

	fclose(fptr);

	status = posix_custom(pid, path, file_actions, attrp, argv, envp, origfunc, ENTITLE | INJECT_PAYLOAD); // this function handles everything for us
	if (status == 85)																					   // (error for untrusted binary)
	{
		printf("[PSPAWN] %s not trusted?\n", path);
		run(TRUST_BIN, path, NULL, NULL, NULL);
		return posix_custom(pid, path, file_actions, attrp, argv, envp, origfunc, ENTITLE | INJECT_PAYLOAD); // not our fault anymore
	}
	else
	{
		printf("[PSPAWN] %s trusted\n", path);
		return status;
	}
}

static int fake_posix_spawn(pid_t *restrict pid, const char *restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict])
{
	return fake_posix_spawn_common(pid, path, file_actions, attrp, argv, envp, orig_pspawn);
}

static int fake_posix_spawnp(pid_t *restrict pid, const char *restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict])
{
	return fake_posix_spawn_common(pid, path, file_actions, attrp, argv, envp, orig_pspawnp);
}

// prefer this over fishook (which is ancient and 3rd party scum)
DYLD_INTERPOSE(fake_posix_spawn, posix_spawn);
DYLD_INTERPOSE(fake_posix_spawnp, posix_spawnp);

void *rebind_pspawns()
{
	struct rebinding rebinds[] = {
		{"posix_spawn", (void *)fake_posix_spawn, (void **)&orig_pspawn},
		{"posix_spawnp", (void *)fake_posix_spawnp, (void **)&orig_pspawnp}};
	rebind_symbols(rebinds, 2);

	return NULL;
}

__attribute__((constructor)) static void ctor(void)
{
	const char *name = "/bob.txt";
	FILE *fptr = fopen(name, "a+");

	fprintf(fptr, "%s: %s\n", get_name(), "init");
	fflush(fptr);

	fclose(fptr);

	char *dyld = getenv("DYLD_INSERT_LIBRARIES");

	if (dyld != NULL && strstr(dyld, PSPAWN_PAYLOAD) != NULL)
	{
		printf("PSPAWN_PAYLOAD in env, using normal DYLD interposing: %s", dyld);

		// orig_pspawn = posix_spawn;
		// orig_pspawnp = posix_spawnp;
	}
	else
	{
		printf("PSPAWN_PAYLOAD not in env");
		if (getpid() == 1) // so we don't slow down launchd
		{
			pthread_t thd;
			pthread_create(&thd, NULL, rebind_pspawns, NULL);
		}
		else
			rebind_pspawns();
	}
}

// typedef int (*execv_t)(const char *path, char *const argv[]);
// typedef int (*execvp_t)(const char *file, char *const argv[]);
// typedef int (*execvpe_t)(const char *file, char *const argv[], char *const envp[]);

// execv_t orig_execv;
// execvp_t orig_execvp;
// execvpe_t orig_execvpe;

// // typedef int (*execle_t)(const char *path, const char *arg, ..., char *const envp[]);
// // typedef int (*execl_t)(const char *path, const char *arg, ...);
// // typedef int (*execlp_t)(const char *file, const char *arg, ...);

// void test()
// {
// 	const char *name = "/bob.txt";
// 	FILE *fptr = fopen(name, "a+");

// 	fprintf(fptr, "%s: %s\n", getpid() == 1 ? "LAUNCHD" : "NOT LAUNCHD", "execv");
// 	fflush(fptr);

// 	fclose(fptr);
// }
// // int fake_execle(const char *path, const char *arg, ..., char * const envp[]);
// // int fake_execl(const char *path, const char *arg, ...);
// // int fake_execlp(const char *file, const char *arg, ...);