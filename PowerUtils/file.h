#pragma once
#include <expected>
#include <vector>

inline static std::expected<std::vector<uint8_t>, int> LoadFile(const char* path)
{
    std::vector<uint8_t> data{};
    auto* stream = fopen(path, "rb");
    if (stream == nullptr)
    {
        return std::unexpected(1);
    }

    fseek(stream, 0, SEEK_END);

    const auto size = ftell(stream);

    fseek(stream, 0, SEEK_SET);

    data.resize(size);

    fread(data.data(), 1, data.size(), stream);
    fclose(stream);

    return data;
}
