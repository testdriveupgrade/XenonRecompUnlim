#pragma once
#include <string>
#include <cstdint>

enum SymbolType
{
    Symbol_None,
    Symbol_Section,
    Symbol_Function,
    Symbol_Comment,
};

struct Symbol
{
    std::string name{};
    uint32_t address{};
    uint32_t size{};
    SymbolType type{};
};

struct SymbolComparer
{
    using is_transparent = void;

    bool operator()(const Symbol& lhs, size_t rhs) const
    {
        return rhs > lhs.address + lhs.size;
    }

    bool operator()(size_t lhs, const Symbol& rhs) const
    {
        return lhs < rhs.address;
    }

    bool operator()(const Symbol& lhs, const Symbol& rhs) const
    {
        return (lhs.address + lhs.size) < rhs.address;
    }
};
