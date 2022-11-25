#include "common.h"

pspawn_t orig_pspawn, orig_pspawnp = (pspawn_t)NULL;
execve_t orig_execve = (execve_t)NULL;

char *get_name()
{
	char *pathbuf = calloc(PROC_PIDPATHINFO_MAXSIZE, sizeof(char));
	return proc_pidpath(getpid(), pathbuf, PROC_PIDPATHINFO_MAXSIZE) > 0 ? pathbuf : "Failed";
}

// void *fake_dlopen( char *filename, int flags, dlopen_t origfunc)
// there's an entitlement for this, check electra

int status = 0;
int current_process = 0;

int fake_posix_spawn_common(pid_t *pid, char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *argv[], char *envp[], pspawn_t origfunc)
{
	// if (strcmp(get_name(), xpcproxy) == 0)
	// 	abort();

	char *name = "/bob.txt";
	FILE *fptr = fopen(name, "a+");

	fprintf(fptr, "posix_spawn:- Parent: %s -> child: %s\n", get_name(), path);

	uint32_t flags = 0;
	if (envp != NULL)
	{
		char *bob = malloc(1000);
		strcpy(bob, envp[0]);
	}
	char *bob = malloc(1000);
	for (char **i = envp;; i++)
	{

		if (i == NULL || *i == NULL)		  // can't put it in for loop because it runs after the code and strstr(NULL, ...) errors
			flags = ENTITLE | INJECT_PAYLOAD; // either end was reached or malformed envp was provided (NULL as entery, not at end)
		else if (strstr(*i, ENV_VAR))
			flags = strtol(*i + strlen(ENV_VAR), NULL, 10);

		if (flags)
			break; // break if flag was set at either point
	}

	fprintf(fptr, "%s%s\n", flags & ENTITLE ? "Entitling," : "", flags & INJECT_PAYLOAD ? "Injecting" : "");
	fflush(fptr);
	fclose(fptr);

	if (strcmp(path, xpcproxy) == 0)													  // journey for xpcproxy stops here - may live to regret it, remember how it execs?
		return posix_custom(pid, path, file_actions, attrp, argv, envp, origfunc, flags); // crashes if I give it the typical entitlements TODO: figure out which ones (or if that's even the issue here)

	status = posix_custom(pid, path, file_actions, attrp, argv, envp, origfunc, flags); // this function handles everything for us
	if (status == 85)																	// (error for untrusted binary)
	{
		// trust_bin((char **)&path, 1);

		printf("[PSPAWN] %s not trusted?\n", path);
		run(TRUST_BIN, path, NULL, NULL, origfunc);

		return posix_custom(pid, path, file_actions, attrp, argv, envp, origfunc, flags); // not our fault anymore
	}
	else
	{
		printf("[PSPAWN] %s trusted\n", path);
		return status;
	}
}

int fake_posix_spawn(pid_t *pid, char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *argv[], char *envp[])
{
	return fake_posix_spawn_common(pid, path, file_actions, attrp, argv, envp, orig_pspawn);
}

int fake_posix_spawnp(pid_t *pid, char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *argv[], char *envp[])
{
	return fake_posix_spawn_common(pid, path, file_actions, attrp, argv, envp, orig_pspawnp);
}

int fake_execve(char *pathname, char *argv[], char *envp[]) // handles all execv*
{
	char *name = "/bob.txt";
	FILE *fptr = fopen(name, "a+");

	fprintf(fptr, "Execve:- Parent: %s -> child: %s\n", get_name(), pathname);

	fflush(fptr);
	fclose(fptr);

	return orig_execve(pathname, argv, envp);
}

// typedef int (*execvp_t)( char *file, char * argv[]);
// typedef int (*execvpe_t)( char *file, char * argv[], char * envp[]);

// execv_t orig_execv;
// execvp_t orig_execvp;
// execvpe_t orig_execvpe;

// // typedef int (*execle_t)( char *path,  char *arg, ..., char * envp[]);
// // typedef int (*execl_t)( char *path,  char *arg, ...);
// // typedef int (*execlp_t)( char *file,  char *arg, ...);

// void test()
// {
// 	 char *name = "/bob.txt";
// 	FILE *fptr = fopen(name, "a+");

// 	fprintf(fptr, "%s: %s\n", getpid() == 1 ? "LAUNCHD" : "NOT LAUNCHD", "execv");
// 	fflush(fptr);

// 	fclose(fptr);
// }
// // int fake_execle( char *path,  char *arg, ..., char *  envp[]);
// // int fake_execl( char *path,  char *arg, ...);
// // int fake_execlp( char *file,  char *arg, ...);