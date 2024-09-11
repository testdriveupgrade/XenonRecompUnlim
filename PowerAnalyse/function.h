#pragma once
#include <vector>

#ifdef _DEBUG(X)
#define DEBUG(X) X
#else
#define DEBUG(X)
#endif

struct Function
{
    struct Block
    {
        size_t base{};
        size_t size{};
        DEBUG(size_t parent{});

        // scratch
        size_t projectedSize{ static_cast<size_t>(-1) };
    };

    size_t base{};
    size_t size{};
    std::vector<Block> blocks{};
    
    size_t SearchBlock(size_t address) const;
    static Function Analyze(const void* code, size_t size, size_t base);
};
