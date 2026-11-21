#include <stdatomic.h>
#include <stdint.h>

volatile uint64_t step_watch_value;

int library_wait(atomic_int *ready, atomic_int *release)
{
    atomic_store_explicit(ready, 1, memory_order_release);
    while (!atomic_load_explicit(release, memory_order_acquire)) {
        uint64_t next = step_watch_value + 1;
        step_watch_value = next;
        step_watch_value = next;
    }
    return 11;
}
