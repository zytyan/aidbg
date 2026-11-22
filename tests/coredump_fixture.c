#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <unistd.h>

#ifdef BUILD_DSO
unsigned char core_dso_data = 0x45;
unsigned char core_dso_bss[256 * 1024];
#else
extern unsigned char core_dso_data;
extern unsigned char core_dso_bss[];
unsigned char core_main_data = 0x3c;

__attribute__((noinline, aligned(65536))) static void cold_marker(void) {
    asm volatile("" ::: "memory");
}

static void *idle_worker(void *arg) {
    (void)arg;
    for (;;)
        pause();
    return NULL;
}

static unsigned char *map(int fd, size_t size, int flags) {
    unsigned char *result = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, fd, 0);
    assert(result != MAP_FAILED);
    return result;
}

static int backing(int directory, const char *name, size_t size) {
    int fd = openat(directory, name, O_RDWR | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0 && ftruncate(fd, size) == 0);
    return fd;
}

static void fill_random(unsigned char *buffer, size_t size) {
    for (size_t offset = 0; offset < size;) {
        ssize_t n = getrandom(buffer + offset, size - offset, 0);
        if (n < 0 && errno == EINTR)
            continue;
        assert(n > 0);
        offset += n;
    }
}

struct request_record {
    struct request_record *next;
    uint64_t sequence;
    uint32_t tenant;
    uint32_t status;
    char route[48];
    char attributes[56];
};

static void fill_typical(unsigned char *cache, size_t size, size_t page) {
    const size_t count = 65536;
    struct request_record *records = calloc(count, sizeof(*records));
    assert(records && sizeof(*records) * count == 8 * 1024 * 1024);
    const char *methods[] = {"read", "list", "write", "validate"};
    for (size_t i = 0; i < count; ++i) {
        struct request_record *record = &records[i];
        record->next = &records[(i + 1) % count];
        record->sequence = 100000 + i;
        record->tenant = i % 256;
        record->status = i % 31 ? 200 : 404;
        snprintf(record->route, sizeof(record->route), "/v1/%s/%u",
                 methods[i % 4], record->tenant);
        snprintf(record->attributes, sizeof(record->attributes),
                 "{\"region\":\"region-%zu\",\"cached\":%s}", i % 8, i % 9 ? "true" : "false");
    }
    printf("objects %p\n", (void *)&records[count - 1].route[0]);

    // Model a small opaque cache beside structured log data and sparsely used space.
    const size_t opaque_end = 1024 * 1024;
    const size_t log_end = 5 * 1024 * 1024;
    fill_random(cache, opaque_end);
    for (size_t i = opaque_end, row = 0; i + 128 <= log_end; ++row) {
        int n = snprintf((char *)cache + i, log_end - i,
                         "request=%zu tenant=%zu route=/v1/%s status=%u duration_us=%zu\n",
                         row, row % 256, methods[row % 4], row % 31 ? 200 : 404,
                         100 + row % 3000);
        assert(n > 0 && n < 128);
        i += n;
    }
    for (size_t i = log_end; i < size; i += 32 * page)
        cache[i] = 0x6b;
    printf("text %p\nsparse %p\n", (void *)(cache + opaque_end), (void *)(cache + log_end));
}

__attribute__((noinline)) static void await_dump(void) {
    volatile unsigned char stack[16 * 1024];
    stack[sizeof(stack) - 1] = 0x73;
    printf("stack %p\nREADY\n", (const void *)&stack[sizeof(stack) - 1]);
    fflush(stdout);
    assert(getchar() == 'x');
    assert(stack[sizeof(stack) - 1] == 0x73);
}

int main(int argc, char **argv) {
    assert(argc == 3);
    int stress = strcmp(argv[2], "stress") == 0;
    assert(stress || strcmp(argv[2], "typical") == 0);
    int directory = open(argv[1], O_RDONLY | O_DIRECTORY);
    assert(directory >= 0);
    assert(prctl(PR_SET_PTRACER, getppid(), 0, 0, 0) == 0 || errno == EINVAL);
    long page = sysconf(_SC_PAGESIZE);
    assert(page > 0);
    pthread_t worker;
    assert(pthread_create(&worker, NULL, idle_worker, NULL) == 0);

    int private_fd = backing(directory, "private-map", 3 * page);
    unsigned char *cow = map(private_fd, 3 * page, MAP_PRIVATE);
    cow[0] = 0x61;
    assert(*(volatile unsigned char *)(cow + page) == 0);
    cow[2 * page] = 0x62;

    int shared_fd = backing(directory, "shared-map", 3 * page);
    unsigned char *shared = map(shared_fd, 3 * page, MAP_SHARED);
    shared[page] = 0x63;

    int ipc_fd = memfd_create("aidbg-ipc", 0);
    assert(ipc_fd >= 0 && ftruncate(ipc_fd, page) == 0);
    unsigned char *ipc = map(ipc_fd, page, MAP_SHARED);
    ipc[0] = 0x64;
    assert(mprotect(ipc, page, PROT_READ) == 0);

    int short_fd = backing(directory, "short-map", stress ? page : 2 * page);
    unsigned char *short_map = map(short_fd, 2 * page, MAP_PRIVATE);
    int protected_fd = backing(directory, "protected-map", page);
    unsigned char *protected = map(protected_fd, 2 * page, MAP_PRIVATE);
    protected[0] = 0x6d;
    assert(mprotect(protected, 2 * page, PROT_NONE) == 0);
    size_t anonymous_size = (stress ? 18 : 10) * 1024 * 1024;
    unsigned char *anonymous = map(-1, anonymous_size, MAP_PRIVATE | MAP_ANONYMOUS);
    if (stress)
        fill_random(anonymous, anonymous_size);
    else
        fill_typical(anonymous, anonymous_size, page);
    anonymous[0] = 0x68;
    anonymous[anonymous_size - 1] = 0x6a;
    core_dso_bss[128 * 1024] = 0x69;
    printf("protected %p\nunbacked %p\n", (void *)protected, (void *)(protected + page));
    printf("main_data %p\ndso_data %p\ndso_bss %p\ncow %p\nclean %p\ncow_end %p\n"
           "shared %p\nipc %p\nshort %p\nanonymous %p\nanonymous_end %p\ncode %p\n",
           (void *)&core_main_data, (void *)&core_dso_data, (void *)&core_dso_bss[128 * 1024],
           (void *)cow, (void *)(cow + page), (void *)(cow + 2 * page),
           (void *)(shared + page), (void *)ipc, (void *)(short_map + page),
           (void *)anonymous, (void *)(anonymous + anonymous_size - 1), (void *)&cold_marker);
    await_dump();
    puts("DONE");
    return 0;
}
#endif
