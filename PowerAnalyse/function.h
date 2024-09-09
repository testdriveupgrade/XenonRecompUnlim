#pragma once
#include <vector>

struct function
{
    struct block
    {
        size_t base;
        size_t size;
    };

    size_t base{};
    size_t size{};
    std::vector<block> blocks{};

    size_t SearchBlock(size_t address) const;
    static function Analyze(const void* code, size_t size, size_t base);
};
