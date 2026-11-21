namespace inspect_case {
struct Base {
    int inherited;
};

struct Values : Base {
    int array[3];
    int *pointer;
};

int global = 42;
int *null_pointer;
Values object{{-9}, {4, 5, 6}, &global};
}

__attribute__((always_inline)) inline int wait_with_locals(int *ready, int *release)
{
    volatile int local = -17;
    [[maybe_unused]] int discarded = __atomic_load_n(release, __ATOMIC_RELAXED);
    __atomic_store_n(ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(release, __ATOMIC_ACQUIRE))
        __atomic_signal_fence(__ATOMIC_ACQ_REL);
    return local + 28;
}

extern "C" int library_wait(int *ready, int *release)
{
    return wait_with_locals(ready, release);
}
