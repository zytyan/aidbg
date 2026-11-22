#include "fixture.h"

struct Item {
    unsigned id;
    struct Item *next;
};

static struct Item third = {30, NULL};
static struct Item second = {20, &third};
static struct Item first = {10, &second};
static struct Item *head = &first;

static void remove_next(struct Item *previous)
{
    struct Item *removed = previous->next;
    if (removed) {
        removed->next = NULL;
        previous->next = removed->next;
    }
}

int main(void)
{
    case_start();
    remove_next(head);
    for (struct Item *item = head; item; item = item->next)
        printf("%s%u", item == head ? "" : " ", item->id);
    puts("");
    return 0;
}
