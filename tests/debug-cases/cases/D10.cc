#include "fixture.h"

#include <array>
#include <cstring>
#include <string_view>

class Reader {
public:
    std::string_view read(const char (&name)[6])
    {
        std::memcpy(buffer.data(), name, buffer.size());
        return {buffer.data(), buffer.size() - 1};
    }

private:
    std::array<char, 6> buffer{};
};

int main()
{
    case_start();
    Reader reader;
    auto first = reader.read("north");
    auto second = reader.read("south");
    printf("%.*s %.*s\n", static_cast<int>(first.size()), first.data(),
           static_cast<int>(second.size()), second.data());
}
