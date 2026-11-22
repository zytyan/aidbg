#include "fixture.h"

#include <stdint.h>

enum { SOURCE_BYTES = 70000, BLOCK_BYTES = 4096 };

static unsigned blocks_for(uint16_t bytes)
{
    return (bytes + BLOCK_BYTES - 1) / BLOCK_BYTES;
}

int main(void)
{
    case_start();
    unsigned bytes = SOURCE_BYTES;
    printf("bytes=%u blocks=%u\n", bytes, blocks_for(bytes));
    return 0;
}
