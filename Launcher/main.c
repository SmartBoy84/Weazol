#include <stdio.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>

#define launchctl "/.Fugu14Untether/bin/launchctl"
#define amfidebilitate "/.Fugu14Untether/amfi/amfidebilitate"
#define amfiplist "/.Fugu14Untether/amfi/com.fugu.debilitate.plist"

void run(char *path, char *arg1, char *arg2, char *arg3)
{
    const char *launch_arg[] = {path, arg1, arg2, arg3};
    pid_t pid;

    posix_spawn(&pid, path, NULL, NULL, (char **)&launch_arg, NULL);
    waitpid(pid, NULL, 0);
}

int main()
{
    run(launchctl, "load", amfiplist, NULL); // super unsafe - what if the user deletes the plist? I don't care
}