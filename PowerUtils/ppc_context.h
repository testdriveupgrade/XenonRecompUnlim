#pragma once
#include <cstdint>

typedef float float128[4];

struct PPCContext
{
    uint64_t iar;
    uint64_t lr;
    uint64_t ctr;

    uint32_t xer;
    uint32_t cr[8];
    uint32_t fpcsr;
    uint64_t gpr[32];
    double fpr[32];
    float128 vpr[128];
};
