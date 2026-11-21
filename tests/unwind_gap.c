#include <stdatomic.h>

int library_wait(atomic_int *ready, atomic_int *release)
{
#ifdef KEEP_FRAME_POINTER
    volatile int result = 11;
#else
    /* Make the frame-pointer fallback unavailable before signaling readiness. */
#if defined(__x86_64__)
    __asm__ volatile("xor %%ebp, %%ebp" ::: "rbp", "cc", "memory");
#elif defined(__aarch64__)
    __asm__ volatile("mov x29, xzr" ::: "x29", "memory");
#endif
    const int result = 11;
#endif
    atomic_store_explicit(ready, 1, memory_order_release);
    /* Keep the sampled PC in this function until the snapshot has finished. */
    while (!atomic_load_explicit(release, memory_order_acquire))
        atomic_signal_fence(memory_order_acq_rel);
    return result;
}
