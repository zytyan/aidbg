#include <string>

namespace fixture {
__attribute__((noinline)) void string_argument(const std::string& text)
{
    asm volatile("" : : "r"(&text) : "memory");
}
}

extern "C" int library_wait()
{
    return 0;
}
