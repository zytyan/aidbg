#include "fixture.h"

#include <array>
#include <string_view>

struct Job {
    std::string_view name;
    unsigned attempts;
};

static std::array<Job, 3> jobs{{{"fetch", 0}, {"parse", 1}, {"save", 0}}};

static void schedule_retry()
{
    for (auto job : jobs) {
        if (job.attempts == 0)
            ++job.attempts;
    }
}

int main()
{
    case_start();
    schedule_retry();
    for (const auto &job : jobs)
        printf("%.*s=%u\n", static_cast<int>(job.name.size()), job.name.data(), job.attempts);
}
