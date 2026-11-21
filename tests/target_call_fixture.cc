#include <csignal>
#include <cstdlib>

namespace call_case {
alignas(4096) unsigned char scratch[8192];
int calls;
volatile sig_atomic_t caught_signal;
volatile int blocking;
static int *signal_release;
static bool hold_signal;

static void on_signal(int)
{
    caught_signal = 1;
    while (hold_signal && !__atomic_load_n(signal_release, __ATOMIC_ACQUIRE))
        __atomic_signal_fence(__ATOMIC_ACQ_REL);
}

int add(int one, int two)
{
    ++calls;
    volatile int sum = one + two;
    return sum;
}

double add(int one, double two)
{
    return one + two;
}
}

extern "C" int call_read(const volatile int *p)
{
    return *p;
}

extern "C" int call_spin()
{
    while (!call_case::blocking)
        __atomic_signal_fence(__ATOMIC_ACQ_REL);
    return 0;
}

extern "C" int call_throw()
{
    throw 3;
}

extern "C" int library_wait(int *ready, int *release)
{
    call_case::hold_signal = std::getenv("AIDBG_TEST_HOLD_SIGNAL") != nullptr;
    call_case::signal_release = release;
    if (std::signal(SIGUSR2, call_case::on_signal) == SIG_ERR)
        return 0;
    __atomic_store_n(ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(release, __ATOMIC_ACQUIRE))
        __atomic_signal_fence(__ATOMIC_ACQ_REL);
    return 11;
}
