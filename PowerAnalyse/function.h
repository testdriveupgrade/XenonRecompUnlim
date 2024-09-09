#pragma once
#include <vector>

struct Function
{
    struct Block
    {
        size_t base{};
        size_t size{};

        // scratch
        size_t projectedSize{ static_cast<size_t>(-1) };
    };

    size_t base{};
    size_t size{};
    std::vector<Block> blocks{};

    size_t SearchBlock(size_t address) const;
    static Function Analyze(const void* code, size_t size, size_t base);
};
