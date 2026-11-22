#define _POSIX_C_SOURCE 200809L
#include "fixture.h"

#include <pthread.h>

static pthread_mutex_t catalog = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t ledger = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t checkpoint;

static void *refresh(void *argument)
{
    (void)argument;
    pthread_mutex_lock(&catalog);
    puts("refresh started");
    pthread_barrier_wait(&checkpoint);
    pthread_mutex_lock(&ledger);
    pthread_mutex_unlock(&ledger);
    pthread_mutex_unlock(&catalog);
    return NULL;
}

static void *reconcile(void *argument)
{
    (void)argument;
    pthread_mutex_lock(&ledger);
    puts("reconcile started");
    pthread_barrier_wait(&checkpoint);
    pthread_mutex_lock(&catalog);
    pthread_mutex_unlock(&catalog);
    pthread_mutex_unlock(&ledger);
    return NULL;
}

int main(void)
{
    case_start();
    pthread_t refresher, reconciler;
    if (pthread_barrier_init(&checkpoint, NULL, 2) ||
        pthread_create(&refresher, NULL, refresh, NULL) ||
        pthread_create(&reconciler, NULL, reconcile, NULL))
        return EXIT_FAILURE;
    pthread_join(refresher, NULL);
    pthread_join(reconciler, NULL);
    pthread_barrier_destroy(&checkpoint);
    puts("completed");
    return 0;
}
