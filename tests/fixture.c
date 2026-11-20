#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

static atomic_int ready, release;
extern int library_wait(atomic_int *, atomic_int *);

static void handler(int signal)
{
    (void)signal;
}

static void *wait_for_release(void *unused)
{
    (void)unused;
    pthread_setname_np(pthread_self(), "aidbg-worker");
    while (!atomic_load_explicit(&ready, memory_order_acquire))
        sched_yield();
    dprintf(STDOUT_FILENO, "READY\n");
    char command;
    while (read(STDIN_FILENO, &command, 1) < 0) {}
    atomic_store_explicit(&release, 1, memory_order_release);
    return NULL;
}

static void *short_lived(void *unused)
{
    return unused;
}

static void *churn(void *unused)
{
    (void)unused;
    while (!atomic_load_explicit(&release, memory_order_acquire)) {
        pthread_t th;
        if (pthread_create(&th, NULL, short_lived, NULL) == 0)
            pthread_join(th, NULL);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    /* Restrict this test opt-in to the runner and its descendants under Yama. */
    if (prctl(PR_SET_PTRACER, getppid(), 0, 0, 0) != 0)
        return 3;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0)
        return 3;
    struct sigaction action = {.sa_handler = handler};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) != 0 || kill(getpid(), SIGUSR1) != 0)
        return 3;
    pthread_t worker, churner;
    int run_churn = argc == 2 && strcmp(argv[1], "--churn") == 0;
    if (run_churn && pthread_create(&churner, NULL, churn, NULL) != 0)
        return 3;
    if (pthread_create(&worker, NULL, wait_for_release, NULL) != 0)
        return 3;
    int result = library_wait(&ready, &release);
    pthread_join(worker, NULL);
    if (run_churn)
        pthread_join(churner, NULL);
    puts("DONE");
    return result == 11 ? 0 : 4;
}
