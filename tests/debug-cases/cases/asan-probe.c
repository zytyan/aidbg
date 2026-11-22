#include <stdlib.h>

int main(void)
{
    volatile unsigned char *byte = malloc(1);
    if (!byte)
        return EXIT_FAILURE;
    *byte = 1;
    free((void *)byte);
    return EXIT_SUCCESS;
}
