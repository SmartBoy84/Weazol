#include <stdio.h>
#include <spawn.h>
#include "fishhook.h"
#include "include/jbd.h"

#define GENERAL_LOG_PATH "/tmp/pspawn_payload_general.log"
#define LAUNCHD_LOG_PATH "/tmp/pspawn_payload_launchd.log"

typedef int (*pspawn_t)(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *const *argv, char *const *envp);

pspawn_t orig_pspawn, orig_pspawnp, orig_testhook;

int fake_posix_spawn_common(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *const argv[], char *const envp[], pspawn_t origfunc)
{
	printf("Hooked posix_spawn\n");

	const char *name = "/bob.txt";
	FILE *fptr = fopen(name, "a+");

	fprintf(fptr, "%s", path);
	fclose(fptr);
	return origfunc(pid, path, file_actions, attrp, argv, envp);
}

void test_hook_fake()
{
	run("/bin/echo", "HOOKED!", NULL, NULL);
}

int fake_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *const argv[], char *const envp[])
{
	return fake_posix_spawn_common(pid, path, file_actions, attrp, argv, envp, orig_pspawn);
}

int fake_posix_spawnp(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *const argv[], char *const envp[])
{
	return fake_posix_spawn_common(pid, path, file_actions, attrp, argv, envp, orig_pspawnp);
}

__attribute__((constructor)) static void ctor(void)
{
	//
	struct rebinding rebinds[] = {
		{"posix_spawn", (void *)fake_posix_spawn, (void **)&orig_pspawn},
		{"posix_spawnp", (void *)fake_posix_spawnp, (void **)&orig_pspawnp},
		{"test_hook", (void *)test_hook_fake, (void **)&orig_testhook}};
	rebind_symbols(rebinds, 3);
}
