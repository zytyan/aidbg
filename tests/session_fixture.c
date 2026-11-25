#include <errno.h>
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/mman.h>
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

struct Spec03Packet {
    uint32_t ack : 1;
    uint32_t req : 4;
    uint32_t : 3;
    uint8_t unused[3];
    union {
        uint32_t ipv4;
        uint8_t ipv6[16];
    };
    uint32_t type;
    _Alignas(16) void *ptr;
};

#pragma pack(push, 1)
struct Spec03Packed {
    uint8_t kind;
    _Alignas(16) uint32_t length;
};
struct Spec03ZeroWidth {
    char a;
    unsigned field : 30;
    unsigned : 0;
    char b;
};
#pragma pack(pop)

struct Spec03Unnamed {
    char a;
    unsigned : 31;
    char b;
};

union Spec03ZeroWidthUnion {
    unsigned : 0;
    char a;
};

__attribute__((used, noinline))
unsigned Spec03Packet_function(void)
{
    return sizeof(struct Spec03Packet);
}

struct Spec03Packet spec03_packet = {.ack = 1, .req = 13, .ipv4 = 0x12345678, .type = 1};
const uint32_t spec03_layout[] = {
    sizeof(struct Spec03Packet), _Alignof(struct Spec03Packet),
    offsetof(struct Spec03Packet, unused), offsetof(struct Spec03Packet, ipv4),
    offsetof(struct Spec03Packet, type), offsetof(struct Spec03Packet, ptr),
    sizeof(struct Spec03Packed), _Alignof(struct Spec03Packed), offsetof(struct Spec03Packed, length),
    sizeof(struct Spec03ZeroWidth), _Alignof(struct Spec03ZeroWidth), offsetof(struct Spec03ZeroWidth, b),
    sizeof(struct Spec03Unnamed), _Alignof(struct Spec03Unnamed), offsetof(struct Spec03Unnamed, b),
    sizeof(union Spec03ZeroWidthUnion), _Alignof(union Spec03ZeroWidthUnion),
};
static char spec03_text[32] = "old";
char *spec03_string = spec03_text;
char *spec03_edge;

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

static inline __attribute__((always_inline)) void inline_scope_probe(struct Packet *copy) {
    fixture_stop(copy);
    asm volatile("" : : "r"(copy) : "memory");
}

static __attribute__((noinline)) int inline_fixture(void) {
    struct Packet copy = packet;
    inline_scope_probe(&copy);
    return 0;
}

static int child_fixture(void) {
    fixture_stop(&packet);
    return 23;
}

static __attribute__((noinline)) int memory_fixture(void) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    char *storage = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (storage == MAP_FAILED || mprotect(storage + page, page, PROT_READ)) return 98;
    spec03_edge = storage + page - 2;
    spec03_edge[0] = 'x';
    fixture_stop(&packet);
    return 23;
}

int main(int argc, char **argv) {
    if (argc > 1 && argv[1][0] == 'i') return inline_fixture();
    if (argc > 1 && argv[1][0] == 'c') return child_fixture();
    if (argc > 1 && argv[1][0] == 'm') return memory_fixture();
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
    if (argc > 1 && argv[1][0] == 'o') {
        pid_t child = fork();
        if (child == 0) _exit(0);
        if (child < 0 || waitpid(child, NULL, 0) != child) return 98;
        puts("stdout tail");
        fputs("stderr tail\n", stderr);
        return 39;
    }
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
