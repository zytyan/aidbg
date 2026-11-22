#include "fixture.h"

enum { READ = 1u << 0, WRITE = 1u << 1, NOTIFY = 1u << 2 };

static unsigned flags = READ | NOTIFY;

static void enable(unsigned requested)
{
    flags = requested;
}

int main(void)
{
    case_start();
    printf("before=%u\n", flags);
    enable(WRITE);
    printf("after=%u\n", flags);
    return 0;
}
