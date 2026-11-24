#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
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

int main(int argc, char **argv) {
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
