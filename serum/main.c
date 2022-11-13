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

void test_hook()
{
	run("/bin/echo", "NOT HOOKED", NULL, NULL);
	sleep(1);
}

int pacify(pid_t source, pid_t target)
{
	addr64_t source_task = read_pointer(find_proc_by_task(source) + __task_offset);
	addr64_t target_task = read_pointer(find_proc_by_task(target) + __task_offset);

	uint64_t target_rop = rk64(target_task + __rop_pid_offset);
	uint64_t target_job = rk64(target_task + __job_pid_offset);
	printf("rop: %x, jop: %x", rk64(source_task + __rop_pid_offset), rk64(source_task + __job_pid_offset));
	return 0;
	wk64(source_task + __rop_pid_offset, target_rop);
	wk64(source_task + __job_pid_offset, target_job);

	uint32_t thread_count = rk32(source_task + __thread_count_offset);
	addr64_t current_thread = read_pointer(source_task + __thread_offset);

	for (int i = 0; i < thread_count; i++)
	{
		wk64(current_thread + __thread_rop_pid_offset, target_rop);
		wk64(current_thread + __thread_job_pid_offset, target_job);
		current_thread = read_pointer(current_thread);
	}
}

int main(const int argc, char **argv)
{
	if (getuid() > 0 && safe_elevate(getpid()))
		return 1;

	if (entitle(getpid(), TF_PLATFORM, CS_PLATFORM_BINARY | CS_GET_TASK_ALLOW | CS_DEBUGGED))
	{
		printf("Failed to entitle myself");
		return 1;
	}

	pacify(getpid(), 157);

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
	run(cynject, str, pspawn_payload, NULL);

	for (;;)
		test_hook();

	// run("/bin/echo", "HELLO WORLD!", NULL, NULL);
	return 0;
}