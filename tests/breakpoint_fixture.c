#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
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

static void *work(void *arg)
{
    for (int i = 0; i < 3; ++i)
        hit();
    return arg;
}

MARK static void force_watch(void)
{
    __asm__ volatile("movq $7, %0" : "=m"(watched) : : "memory");
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
    if (argc != 3 || prctl(PR_SET_PTRACER, getppid(), 0, 0, 0) != 0)
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
    anonymous[0] = 0x90; /* nop */
    anonymous[1] = 0xc3; /* ret */
    if (mprotect(anonymous, 4096, PROT_READ | PROT_EXEC) != 0)
        return 3;
    printf("READY %p %p %p %p %p %p %p %p %p %p %p\n", (void *)hit,
           (void *)slot_two, (void *)slot_three, (void *)slot_four,
           (void *)slot_five, one, two, three, (void *)bss_buffer,
           (void *)&watched, (void *)anonymous);
    fflush(stdout);
    int command;
    while ((command = getchar()) != EOF && command != 'q') {
        if (command == 'r') {
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
