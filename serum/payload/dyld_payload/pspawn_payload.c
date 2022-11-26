#include "common.h"

DYLD_INTERPOSE(fake_dlopen, dlopen);

DYLD_INTERPOSE(fake_posix_spawn, posix_spawn);
DYLD_INTERPOSE(fake_posix_spawnp, posix_spawnp);

DYLD_INTERPOSE(fake_execv, execv);
DYLD_INTERPOSE(fake_execve, execve);
DYLD_INTERPOSE(fake_execvp, execvp);

__attribute__((constructor)) static void ctor(void)
{
	logging = 0;

	const char *name = "/bob.txt";
	FILE *fptr = fopen(name, "a+");

	fprintf(fptr, "%s: %s\n", get_name(), "dyld: init");

	char *flags_var; // ideally I should do STRLEN(ENV_VAR) + 32 + 1 to save memory but eh
	if ((flags_var = getenv(ENV_VAR)))
	{
		uint32_t flags;
		flags = strtol(flags_var, NULL, 10);

		// fprintf(fptr, "flags_var: %s, %s%s%s\n", flags_var, CHECK_FLAG(flags, WAS_EXEC) ? "wasexec, " : "", CHECK_FLAG(flags, ENTITLE) ? "[WAS_EXEC] Entitling, " : "", CHECK_FLAG(flags, INJECT_PAYLOAD) ? "Injecting" : "");

		if (CHECK_FLAG(flags, WAS_EXEC)) // see if we need to do things ourselves
		{
			if (CHECK_FLAG(flags, ENTITLE))
				entitle(getpid(), TF_PLATFORM, CS_PLATFORM_BINARY | CS_GET_TASK_ALLOW | CS_DEBUGGED | CS_INSTALLER);
		}
	}
	else
		fprintf(fptr, "[WARNING] ENV_VAR not found; incorrectly injected\n");
	// exit(1); // maybe after we are certain that every launched binary must have this

	fflush(fptr);
	fclose(fptr);

	orig_dlopen = (dlopen_t)dlopen;

	orig_pspawn = (pspawn_t)posix_spawn;
	orig_pspawnp = (pspawn_t)posix_spawnp;

	orig_execve = (execve_t)execve; // we will need to suspend child in its own constructor for this to work OR just override function entirely and call custom_posix with SET_EXEC flag
	orig_execv = (execve_t)execv;	// yes this cast isn't correct but it works so idk
	orig_execvp = (execve_t)execvp; // yes this cast isn't correct but it works so idk
}