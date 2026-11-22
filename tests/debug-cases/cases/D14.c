#include "fixture.h"

#include <string.h>

static char *copy_label(const char *source)
{
    size_t length = strlen(source);
    char *label = malloc(length);
    if (label) {
        memcpy(label, source, length);
        label[length] = '\0';
    }
    return label;
}

int main(void)
{
    case_start();
    char *label = copy_label("queued");
    if (!label)
        return EXIT_FAILURE;

    puts(label);
    free(label);
    return 0;
}
