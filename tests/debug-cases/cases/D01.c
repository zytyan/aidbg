#include "fixture.h"

struct Profile {
    unsigned quota;
};

struct Account {
    unsigned id;
    const struct Profile *profile;
};

static const struct Profile default_profile = {64};
static const struct Account accounts[] = {{7, &default_profile}, {9, NULL}};

static unsigned quota_for(const struct Account *account)
{
    return account->profile->quota;
}

int main(void)
{
    case_start();
    printf("account=%u quota=%u\n", accounts[0].id, quota_for(&accounts[0]));
    printf("account=%u quota=%u\n", accounts[1].id, quota_for(&accounts[1]));
    return 0;
}
