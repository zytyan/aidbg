#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define MARK __attribute__((noinline, noclone))

static atomic_int calls;
static volatile uint64_t watched = 7;

MARK static void hit(void) { atomic_fetch_add_explicit(&calls, 1, memory_order_relaxed); }
MARK static void slot_two(void) { __asm__ volatile(""); }
MARK static void slot_three(void) { __asm__ volatile(""); }
MARK static void slot_four(void) { __asm__ volatile(""); }
MARK static void slot_five(void) { __asm__ volatile(""); }

static volatile sig_atomic_t signals_seen;
static char bss_buffer[32768];

static void handle_trap(int sig)
{
    if (sig == SIGTRAP)
        ++signals_seen;
}

static pthread_barrier_t ready;
static pthread_barrier_t release;

static void *work(void *arg)
{
    for (int i = 0; i < 3; ++i)
        hit();
    return arg;
}

static void *selected_worker(void *arg)
{
    printf("THREAD %d\n", gettid());
    pthread_barrier_wait(&ready);
    pthread_barrier_wait(&release);
    return work(arg);
}

MARK static void force_watch(void)
{
#if defined(__x86_64__)
    __asm__ volatile("movq $7, %0" : "=m"(watched) : : "memory");
#else
    watched = 7;
#endif
}

static void *write_values(void *arg)
{
    force_watch();
    watched = 9;
    return arg;
}

static void *load(const char *library, Lmid_t namespace)
{
    void *handle = dlmopen(namespace, library, RTLD_LOCAL | RTLD_NOW);
    if (!handle)
        fprintf(stderr, "%s\n", dlerror());
    return handle ? dlsym(handle, "library_wait") : NULL;
}

int main(int argc, char **argv)
{
    if (argc != 3)
        return 3;
    if (prctl(PR_SET_PTRACER, getppid(), 0, 0, 0) != 0 && errno != EINVAL)
        return 3;
    struct sigaction action = {.sa_handler = handle_trap};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTRAP, &action, NULL) != 0)
        return 3;
    void *one = load(argv[1], LM_ID_BASE);
    void *two = load(argv[1], LM_ID_NEWLM);
    void *three = load(argv[2], LM_ID_BASE);
    if (!one || !two || !three)
        return 3;
    unsigned char *anonymous = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (anonymous == MAP_FAILED)
        return 3;
#if defined(__aarch64__)
    static const unsigned char instructions[] = {
        0x1f, 0x20, 0x03, 0xd5, /* nop */
        0xc0, 0x03, 0x5f, 0xd6, /* ret */
    };
#elif defined(__x86_64__)
    static const unsigned char instructions[] = {0x90, 0xc3}; /* nop, ret */
#endif
    memcpy(anonymous, instructions, sizeof instructions);
    if (mprotect(anonymous, 4096, PROT_READ | PROT_EXEC) != 0)
        return 3;
    printf("READY %p %p %p %p %p %p %p %p %p %p %p\n", (void *)hit,
           (void *)slot_two, (void *)slot_three, (void *)slot_four,
           (void *)slot_five, one, two, three, (void *)bss_buffer,
           (void *)&watched, (void *)anonymous);
    fflush(stdout);
    pthread_t selected;
    if (pthread_barrier_init(&ready, NULL, 2) || pthread_barrier_init(&release, NULL, 2))
        return 3;
    int command;
    while ((command = getchar()) != EOF && command != 'q') {
        if (command == 't') {
            if (pthread_create(&selected, NULL, selected_worker, NULL) != 0)
                return 3;
            pthread_barrier_wait(&ready);
        } else if (command == 'g') {
            int before = atomic_load_explicit(&calls, memory_order_relaxed);
            pthread_barrier_wait(&release);
            work(NULL);
            if (pthread_join(selected, NULL) != 0 ||
                atomic_load_explicit(&calls, memory_order_relaxed) != before + 6)
                return 3;
            puts("JOINED");
        } else if (command == 'r') {
            printf("READ %llu\n", (unsigned long long)watched);
        } else if (command == 'w') {
            pthread_t writer;
            if (pthread_create(&writer, NULL, write_values, NULL) != 0)
                return 3;
            pthread_join(writer, NULL);
            puts("WRITTEN");
        } else if (command == 'f') {
            pid_t child = fork();
            if (child == 0) {
                hit();
                _exit(0);
            }
            int status;
            if (child < 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status))
                return 3;
            hit();
            puts("FORKED");
        } else if (command == 'x') {
            int before = atomic_load_explicit(&calls, memory_order_relaxed);
            pthread_t thread;
            if (pthread_create(&thread, NULL, work, NULL) != 0)
                return 3;
            work(NULL);
            pthread_join(thread, NULL);
            if (atomic_load_explicit(&calls, memory_order_relaxed) != before + 6)
                return 3;
            raise(SIGTRAP);
            printf("DONE %d\n", (int)signals_seen);
        } else {
            return 4;
        }
        fflush(stdout);
    }
    return command == 'q' ? 0 : 4;
}
