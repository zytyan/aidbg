#include <errno.h>
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

struct Node {
    struct Node *next;
    int32_t value;
};

struct Packet {
    uint32_t length;
    union {
        uint32_t word;
        uint8_t octets[4];
    } payload;
    struct Node *node;
    uint16_t tail[3];
    unsigned flag : 3;
};

struct Node nodes[] = {{&nodes[1], 12}, {NULL, 29}};
struct Packet packet = {3, {.word = 0x12345678}, nodes, {4, 9, 15}, 5};
volatile uint32_t watched = 33;
volatile uint32_t watched_copy;
volatile sig_atomic_t signal_count;

__attribute__((noinline)) int32_t fixture_sum(int32_t a, int32_t b) {
    return a + b;
}

__attribute__((noinline)) void fixture_stop(struct Packet *argument) {
    asm volatile("" : : "r"(argument) : "memory");
}

static void on_signal(int number) {
    (void)number;
    signal_count++;
}

static void *event_worker(void *argument) {
    fixture_stop(argument);
    return NULL;
}

static int event_fixture(void) {
    pthread_t workers[2];
    if (pthread_create(&workers[0], NULL, event_worker, &packet) ||
        pthread_create(&workers[1], NULL, event_worker, &packet))
        return 91;
    pthread_join(workers[0], NULL);
    pthread_join(workers[1], NULL);
    signal(SIGUSR1, on_signal);
    raise(SIGUSR1);
    char input[80];
    puts("enter data");
    fputs("stderr ready\n", stderr);
    fflush(stdout);
    if (!fgets(input, sizeof(input), stdin)) return 92;
    printf("received %s", input);
    return signal_count == 1 ? 37 : 93;
}

static int child_fixture(void) {
    fixture_stop(&packet);
    return 23;
}

int main(int argc, char **argv) {
    if (argc > 1 && argv[1][0] == 'c') return child_fixture();
    if (argc > 1 && argv[1][0] == 'k') {
        pid_t child = fork();
        if (child == 0) {
            execl(argv[0], argv[0], "child", (char *)NULL);
            _exit(96);
        }
        int status;
        return child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status)
            ? WEXITSTATUS(status) : 97;
    }
    if (argc > 2 && argv[1][0] == 'd') {
        for (int i = 0; i < 2; ++i) {
            void *library = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
            if (!library) return 94;
            int (*function)(int) = (int (*)(int))dlsym(library, "fixture_linked");
            if (!function || function(i) != i + 9 || dlclose(library) != 0) return 95;
        }
        return 24;
    }
    if (argc > 1 && argv[1][0] == 'e') return event_fixture();
    if (argc > 1 && argv[1][0] == 'f') {
        volatile uintptr_t inaccessible = 0;
        return *(volatile int *)inaccessible;
    }
    if (argc > 1 && argv[1][0] == 'a') {
        if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0) < 0) return errno;
        puts("ready");
        fflush(stdout);
        for (;;) pause();
    }
    signal(SIGUSR1, on_signal);
    fixture_stop(&packet);
    watched_copy = watched;
    watched = 44;
    raise(SIGUSR1);
    fixture_stop(&packet);
    for (;;) pause();
}
