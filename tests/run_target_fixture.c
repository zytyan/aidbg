#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile int *crash_pointer;
static volatile unsigned int watched = 17;

static void update_watched(void)
{
    watched = 42;
}

static void caught(int signal)
{
    (void)signal;
    (void)write(STDOUT_FILENO, "delivered\n", 10);
}

static void *crash(void *argument)
{
    (void)argument;
    int number = *crash_pointer;
    return (void *)(long)number;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    if (strcmp(argv[1], "watch") == 0) {
        const char *label = getenv("AIDBG_TEST_LABEL");
        char line[32];
        if (label == NULL || fgets(line, sizeof(line), stdin) == NULL)
            return 6;
        update_watched();
        printf("%s:%s", label, line);
        return 0;
    }
    if (strcmp(argv[1], "crash") == 0) {
        const struct rlimit limit = {0, 0};
        if (setrlimit(RLIMIT_CORE, &limit) != 0)
            return 3;
        pthread_t worker;
        if (pthread_create(&worker, NULL, crash, NULL) != 0)
            return 3;
        pthread_join(worker, NULL);
        return 4;
    }
    if (strcmp(argv[1], "recover") == 0) {
        struct sigaction handler = {.sa_handler = caught};
        if (sigemptyset(&handler.sa_mask) || sigaction(SIGUSR1, &handler, NULL) || raise(SIGUSR1))
            return 5;
        fputs("target stderr\n", stderr);
        return 7;
    }
    if (strcmp(argv[1], "wait") == 0) {
        for (;;)
            pause();
    }
    if (strcmp(argv[1], "fork") == 0) {
        pid_t child = fork();
        if (child == 0) {
            update_watched();
            _exit(watched == 42 ? 0 : 9);
        }
        int status;
        if (child < 0 || waitpid(child, &status, 0) != child ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0 || watched != 17)
            return 9;
        update_watched();
        printf("forked:%u\n", watched);
        return 0;
    }
    if (strcmp(argv[1], "exec") == 0) {
        execl(argv[0], argv[0], "fork", (char *)NULL);
        return 9;
    }
    if (strcmp(argv[1], "realtime") == 0) {
        const struct rlimit limit = {0, 0};
        if (setrlimit(RLIMIT_CORE, &limit) != 0)
            return 3;
        raise(SIGRTMIN);
        return 8;
    }
    return 2;
}
