#include "common.h"

pspawn_t orig_pspawn, orig_pspawnp = (pspawn_t)NULL;
execve_t orig_execve, orig_execv, orig_execvp = (execve_t)NULL;
dlopen_t orig_dlopen = (dlopen_t)NULL;

char *get_name()
{
	char *pathbuf = calloc(PROC_PIDPATHINFO_MAXSIZE, sizeof(char));
	return proc_pidpath(getpid(), pathbuf, PROC_PIDPATHINFO_MAXSIZE) > 0 ? pathbuf : "Failed";
}

// void *fake_dlopen( char *filename, int flags, dlopen_t origfunc)
// there's an entitlement for this, check electra

int status = 0;
int current_process = 0;

void *fake_dlopen(char *filename, int flag)
{
	char *name = "/bob.txt";
	FILE *fptr = fopen(name, "a+");

	fprintf(fptr, "dlopen*:- Parent: %s -> child: %s\n", get_name(), filename);

	fflush(fptr);
	fclose(fptr);

	// trust_bin(&filename, 1, TC_CREATE_NEW); // add dylib to trustcache - create a separate trustcache for it

	return orig_dlopen(filename, flag);
}

int fake_posix_spawn_common(pid_t *pid, char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *argv[], char *envp[], pspawn_t origfunc)
{
	char *name = "/bob.txt";
	FILE *fptr = fopen(name, "a+");

	fprintf(fptr, "posix_spawn:- Parent: %s -> child: %s\n", get_name(), path);

	uint32_t flags = 0;

	for (char **i = envp;; i++)
	{
		if (i == NULL || *i == NULL)		  // can't put it in for loop because it runs after the code and strstr(NULL, ...) errors
			flags = ENTITLE | INJECT_PAYLOAD; // either end was reached or malformed envp was provided (NULL as entery, not at end)

		else if (strstr(*i, ENV_VAR))
			flags = strtol(*i + strlen(ENV_VAR), NULL, 10);

		if (flags)
			break; // break if flag was set at either point
	}

	fprintf(fptr, "%s%s\n", CHECK_FLAG(flags, ENTITLE) ? "Entitling," : "", CHECK_FLAG(flags, INJECT_PAYLOAD) ? "Injecting" : "");
	fflush(fptr);
	fclose(fptr);

	if (strcmp(path, xpcproxy) != 0) // journey for xpcproxy stops here - may live to regret it, remember how it execs?
		trust_bin(&path, 1, TC_SUB_IN);

	return posix_custom(pid, path, file_actions, attrp, argv, envp, origfunc, flags);
}

int fake_posix_spawn(pid_t *pid, char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *argv[], char *envp[])
{
	return fake_posix_spawn_common(pid, path, file_actions, attrp, argv, envp, orig_pspawn);
}

int fake_posix_spawnp(pid_t *pid, char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *argv[], char *envp[])
{
	return fake_posix_spawn_common(pid, path, file_actions, attrp, argv, envp, orig_pspawnp);
}

// these functions replace currently running process so you will need to start remote process suspended in ctor() (kill signals, look aemonidify)
int fake_execve_common(char *pathname, char *argv[], char *envp[], execve_t origfunc) // handles all execv*
{
	char *name = "/bob.txt";
	FILE *fptr = fopen(name, "a+");

	fprintf(fptr, "execv*:- Parent: %s -> child: %s\n", get_name(), pathname);

	fflush(fptr);
	fclose(fptr);

	run(TRUST_BIN, pathname, NULL, NULL, orig_pspawn); // PATH traversal not supportet yet
	// trust_bin(&pathname, 1, TC_SUB_IN);

	return origfunc(pathname, argv, envp);
}

int fake_execve(char *pathname, char *argv[], char *envp[])
{
	envp = add_var(envp, WAS_EXEC | INJECT_PAYLOAD | ENTITLE);
	return fake_execve_common(pathname, argv, envp, orig_execve);
}

int fake_execv(char *path, char *argv[]) // handles all execv*
{
	environ = add_var(environ, WAS_EXEC | INJECT_PAYLOAD | ENTITLE);
	return fake_execve_common(path, argv, NULL, orig_execv);
}

int fake_execvp(char *file, char *argv[]) // handles all execv*
{
	environ = add_var(environ, WAS_EXEC | INJECT_PAYLOAD | ENTITLE);
	return fake_execve_common(file, argv, NULL, orig_execvp);
}