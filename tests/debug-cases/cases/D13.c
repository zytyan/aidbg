#include "fixture.h"

static int *active_score;
static int *cached_score;

static void replace_score(int *replacement)
{
    free(active_score);
    active_score = replacement;
}

int main(void)
{
    case_start();
    active_score = malloc(sizeof(*active_score));
    int *replacement = malloc(sizeof(*replacement));
    if (!active_score || !replacement)
        return EXIT_FAILURE;

    *active_score = 17;
    *replacement = 23;
    cached_score = active_score;
    replace_score(replacement);
    printf("score=%d\n", *cached_score);
    free(active_score);
    return 0;
}
