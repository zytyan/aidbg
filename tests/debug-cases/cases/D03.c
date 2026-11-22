#define _POSIX_C_SOURCE 200809L
#include "fixture.h"

#include <pthread.h>
#include <stdatomic.h>

static atomic_uint total;
static pthread_barrier_t read_complete;

static void *record(void *argument)
{
    const unsigned amount = *(const unsigned *)argument;
    unsigned before = atomic_load(&total);
    pthread_barrier_wait(&read_complete);
    atomic_store(&total, before + amount);
    return NULL;
}

int main(void)
{
    case_start();
    unsigned amount = 10;
    pthread_t first, second;
    if (pthread_barrier_init(&read_complete, NULL, 2) ||
        pthread_create(&first, NULL, record, &amount) ||
        pthread_create(&second, NULL, record, &amount))
        return EXIT_FAILURE;
    pthread_join(first, NULL);
    pthread_join(second, NULL);
    pthread_barrier_destroy(&read_complete);
    printf("total=%u\n", atomic_load(&total));
    return 0;
}
