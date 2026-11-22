#include <cstdlib>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

struct Leaf { int baz; };
struct Entry { Leaf *bar; };
struct Data { Entry foo[16]; Entry *dynamic; };

#ifndef FIXTURE_VALUE
#define FIXTURE_VALUE 42
#endif
Leaf leaf{FIXTURE_VALUE};
Data value{};
Data *g_Data = &value;
Data *g_Null = nullptr;
Data *g_Missing;
unsigned long g_Wide = ~0UL;

void *worker(void *) {
    for (;;) {
        pause();
    }
}

__attribute__((noinline)) void capture_here() {
    volatile int frame_local = 73;
    if (std::getenv("AIDBG_WAIT")) {
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
        if (write(STDOUT_FILENO, "ready\n", 6) != 6) std::abort();
        for (;;) asm volatile("" : : "m"(frame_local));
    }
    __builtin_trap();
}

__attribute__((noinline)) void caller() {
    volatile int caller_local = 91;
    capture_here();
    asm volatile("" : : "m"(caller_local));
}

int main() {
    const long page_size = sysconf(_SC_PAGESIZE);
    void *page = mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED || munmap(page, page_size) != 0) return 1;
    g_Missing = static_cast<Data *>(page);
    value.dynamic = value.foo;
    for (Entry &entry : value.foo) entry.bar = &leaf;
    pthread_t thread;
    if (pthread_create(&thread, nullptr, worker, nullptr) != 0) return 1;
    caller();
}
