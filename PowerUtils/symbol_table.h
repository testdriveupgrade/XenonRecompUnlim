#pragma once
#include "symbol.h"
#include <set>

class SymbolTable : public std::multiset<Symbol, SymbolComparer>
{
public:
    const_iterator find(size_t address) const
    {
        auto iter = std::multiset<Symbol, SymbolComparer>::find(address);
        if (iter == end())
        {
            return iter;
        }

        size_t closest{ address - iter->address };
        auto match = iter;
        for (; iter != end(); ++iter)
        {
            const size_t distance = address - iter->address;
            if (distance <= closest)
            {
                match = iter;
                closest = distance;
            }
        }

        return match;
    }

    iterator find(size_t address)
    {
        auto iter = std::multiset<Symbol, SymbolComparer>::find(address);
        if (iter == end())
        {
            return iter;
        }

        size_t closest{ address - iter->address };
        auto match = iter;
        for (; iter != end(); ++iter)
        {
            const size_t distance = address - iter->address;
            if (distance <= closest)
            {
                match = iter;
                closest = distance;
            }
        }

        return match;
    }
};
