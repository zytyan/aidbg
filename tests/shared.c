#include <stdatomic.h>
#include <sched.h>

__attribute__((noinline)) static int library_leaf(atomic_int *ready, atomic_int *release)
{
    atomic_store_explicit(ready, 1, memory_order_release);
    while (!atomic_load_explicit(release, memory_order_acquire))
        sched_yield();
    return 10;
}

__attribute__((noinline)) int library_wait(atomic_int *ready, atomic_int *release)
{
    return library_leaf(ready, release) + 1;
}
