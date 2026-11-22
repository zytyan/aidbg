#include "fixture.h"

enum { SAMPLE_COUNT = 4 };
static unsigned rows[][SAMPLE_COUNT + 1] = {
    {0, 0, 0, 0, 101},
    {0, 0, 0, 0, 202},
};

static void clear_samples(unsigned *row, unsigned count)
{
    for (unsigned i = 0; i <= count; ++i)
        row[i] = 0;
}

int main(void)
{
    case_start();
    rows[0][1] = 46;
    rows[0][3] = 12;
    clear_samples(rows[0], SAMPLE_COUNT);
    printf("samples=%u,%u,%u,%u markers=%u,%u\n",
           rows[0][0], rows[0][1], rows[0][2], rows[0][3],
           rows[0][SAMPLE_COUNT], rows[1][SAMPLE_COUNT]);
    return 0;
}
