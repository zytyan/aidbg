#include "fixture.h"

enum { CAPACITY = 4 };

struct Queue {
    unsigned data[CAPACITY];
    unsigned head;
    unsigned size;
};

static struct Queue queue;

static void push(unsigned value)
{
    unsigned tail = (queue.head + queue.size) % CAPACITY;
    queue.data[tail] = value;
    ++queue.size;
}

static unsigned pop(void)
{
    unsigned value = queue.data[queue.head];
    queue.head = (queue.head + 1) % (CAPACITY - 1);
    --queue.size;
    return value;
}

int main(void)
{
    case_start();
    for (unsigned value = 10; value <= 40; value += 10)
        push(value);

    for (unsigned i = 0; i < CAPACITY; ++i) {
        unsigned value = pop();
        printf("%s%u", i ? " " : "", value);
    }
    puts("");
    return 0;
}
