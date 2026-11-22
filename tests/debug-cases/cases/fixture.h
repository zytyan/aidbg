#ifndef AIDBG_DEBUG_CASE_FIXTURE_H
#define AIDBG_DEBUG_CASE_FIXTURE_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static inline void case_wait_for_release(const char *release)
{
    if (strcmp(release, "signal:SIGUSR1") == 0) {
        sigset_t signals, previous;
        int received;
        sigemptyset(&signals);
        sigaddset(&signals, SIGUSR1);
        if (sigprocmask(SIG_BLOCK, &signals, &previous) == 0) {
            printf("pid=%ld; waiting for SIGUSR1\n", (long)getpid());
            errno = sigwait(&signals, &received);
            if (!errno && sigprocmask(SIG_SETMASK, &previous, NULL) == 0)
                return;
        }
        perror("SIGUSR1 release");
        exit(EXIT_FAILURE);
    }
    if (strncmp(release, "file:", 5) == 0 && release[5] != '\0') {
        const char *path = release + 5;
        const struct timespec interval = {0, 10000000};
        struct stat metadata;
        printf("pid=%ld; waiting for file %s\n", (long)getpid(), path);
        while (stat(path, &metadata) == -1) {
            if (errno != ENOENT && errno != EINTR) {
                perror(path);
                exit(EXIT_FAILURE);
            }
            nanosleep(&interval, NULL);
        }
        return;
    }
    fputs("AIDBG_WAIT_RELEASE must be signal:SIGUSR1 or file:<path>\n", stderr);
    exit(EXIT_FAILURE);
}

static inline void case_start(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *tracer = getenv("AIDBG_TRACER_PID");
    if (tracer) {
        char *end;
        errno = 0;
        long pid = strtol(tracer, &end, 10);
        if (errno || end == tracer || *end || pid <= 0 || pid > INT_MAX) {
            fputs("AIDBG_TRACER_PID must be a positive PID\n", stderr);
            exit(EXIT_FAILURE);
        }
        if (prctl(PR_SET_PTRACER, (unsigned long)pid, 0UL, 0UL, 0UL) == -1 &&
            errno != EINVAL) {
            perror("PR_SET_PTRACER");
            exit(EXIT_FAILURE);
        }
    }
    const char *release = getenv("AIDBG_WAIT_RELEASE");
    if (release) {
        case_wait_for_release(release);
    } else if (getenv("AIDBG_WAIT")) {
        printf("pid=%ld; press Enter to start\n", (long)getpid());
        (void)getchar();
    }
}

#endif
