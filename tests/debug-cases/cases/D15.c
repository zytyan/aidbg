#include "fixture.h"

struct Report {
    char *buffer;
};

static int prepare(struct Report *report, unsigned records)
{
    report->buffer = malloc(32);
    if (!report->buffer)
        return -1;
    if (records == 0) {
        free(report->buffer);
        return -1;
    }
    return 0;
}

static void close_report(struct Report *report)
{
    free(report->buffer);
}

int main(void)
{
    case_start();
    struct Report report = {0};
    if (prepare(&report, 0) != 0)
        puts("report rejected");
    close_report(&report);
    return 0;
}
