#include "function.h"
#include <disasm.h>
#include <vector>
#include <bit>
#include <algorithm>
#include <cassert>

size_t Function::SearchBlock(size_t address) const
{
    if (address < base)
    {
        return -1;
    }

    for (size_t i = 0; i < blocks.size(); i++)
    {
        const auto& block = blocks[i];
        const auto begin = base + block.base;
        const auto end = begin + block.size;

        if (begin != end)
        {
            if (address >= begin && address < end)
            {
                return i;
            }
        }
        else // fresh block
        {
            if (address == begin)
            {
                return i;
            }
        }
    }

    return -1;
}

Function Function::Analyze(const void* code, size_t size, size_t base)
{
    Function fn{ base, 0 };
    auto& blocks = fn.blocks;
    blocks.reserve(8);
    blocks.emplace_back();

    const auto* data = (uint32_t*)code;
    const auto* dataStart = data;
    const auto* dataEnd = (uint32_t*)((uint8_t*)code + size);
    std::vector<size_t> blockStack{};
    blockStack.reserve(32);
    blockStack.emplace_back();

    #define RESTORE_DATA() if (!blockStack.empty()) data = (dataStart + ((blocks[blockStack.back()].base + blocks[blockStack.back()].size) / sizeof(*data))) - 1; // continue adds one

    // TODO: Branch fallthrough
    for (; data <= dataEnd ; ++data)
    {
        const auto addr = base + ((data - dataStart) * sizeof(*data));
        if (blockStack.empty())
        {
            break; // it's hideover
        }

        auto& curBlock = blocks[blockStack.back()];
        DEBUG(const auto blockBase = curBlock.base);
        const auto instruction = std::byteswap(*data);

        const auto op = PPC_OP(instruction);
        const auto xop = PPC_XOP(instruction);
        const auto isLink = PPC_BL(instruction); // call

        ppc_insn insn;
        ppc::Disassemble(data, addr, insn);

        // Sanity check
        assert(addr == base + curBlock.base  + curBlock.size);
        if (curBlock.projectedSize != -1 && curBlock.size >= curBlock.projectedSize) // fallthrough
        {
            blockStack.pop_back();
            RESTORE_DATA();
            continue;
        }

        curBlock.size += 4;
        if (op == PPC_OP_BC) // conditional branches all originate from one opcode, thanks RISC
        {
            if (isLink) // just a conditional call, nothing to see here
            {
                continue;
            }

            // TODO: carry projections over to false
            curBlock.projectedSize = -1;
            blockStack.pop_back();

            // TODO: Handle absolute branches?
            assert(!PPC_BA(instruction));
            const auto branchDest = addr + PPC_BD(instruction);

            // true/false paths
            // left block: false case
            // right block: true case
            const auto lBase = (addr - base) + 4;
            const auto rBase = (addr + PPC_BD(instruction)) - base;

            // these will be -1 if it's our first time seeing these blocks
            auto lBlock = fn.SearchBlock(base + lBase);

            if (lBlock == -1)
            {
                blocks.emplace_back(lBase, 0).projectedSize = rBase - lBase;
                lBlock = blocks.size() - 1;

                // push this first, this gets overriden by the true case as it'd be further away
                DEBUG(blocks[lBlock].parent = blockBase);
                blockStack.emplace_back(lBlock);
            }

            auto rBlock = fn.SearchBlock(base + rBase);
            if (rBlock == -1)
            {
                blocks.emplace_back(branchDest - base, 0);
                rBlock = blocks.size() - 1;

                DEBUG(blocks[rBlock].parent = blockBase);
                blockStack.emplace_back(rBlock);
            }

            RESTORE_DATA();
        }
        else if (op == PPC_OP_B || instruction == 0 || (op == PPC_OP_CTR && (xop == 16 || xop == 528))) // b, blr, end padding
        {
            if (!isLink)
            {
                blockStack.pop_back();

                if (op == PPC_OP_B)
                {
                    // Tail call, no need to chase
                    if (blocks.size() == 1)
                    {
                        RESTORE_DATA();
                        continue;
                    }

                    assert(!PPC_BA(instruction));
                    const auto branchDest = addr + PPC_BI(instruction);

                    const auto branchBase = branchDest - base;
                    const auto branchBlock = fn.SearchBlock(branchDest);

                    if (branchDest < base)
                    {
                        // Branches before base are just tail calls, no need to chase after those
                        RESTORE_DATA();
                        continue;
                    }

                    // carry over our projection if blocks are next to each other
                    const auto isContinuous = branchBase == curBlock.base + curBlock.size;
                    auto sizeProjection = (size_t)-1;

                    if (curBlock.projectedSize != -1 && isContinuous)
                    {
                        sizeProjection = curBlock.projectedSize - curBlock.size;
                    }

                    if (branchBlock == -1)
                    {
                        blocks.emplace_back(branchBase, 0, sizeProjection);

                        blockStack.emplace_back(blocks.size() - 1);
                        
                        DEBUG(blocks.back().parent = blockBase);
                        RESTORE_DATA();
                        continue;
                    }
                }
                else if (op == PPC_OP_CTR)
                {
                    // 5th bit of BO tells cpu to ignore the counter, which is a blr/bctr otherwise it's conditional
                    const auto conditional = !(PPC_BO(instruction) & 0x10);
                    if (conditional)
                    {
                        // right block's just going to return
                        const auto lBase = (addr - base) + 4;
                        auto lBlock = fn.SearchBlock(lBase);
                        if (lBlock == -1)
                        {
                            blocks.emplace_back(lBase, 0);
                            lBlock = blocks.size() - 1;

                            DEBUG(blocks[lBlock].parent = blockBase);
                            blockStack.emplace_back(lBlock);
                            RESTORE_DATA();
                            continue;
                        }
                    }
                }

                RESTORE_DATA();
            }
        }
        else if (insn.opcode == nullptr)
        {
            blockStack.pop_back();
            RESTORE_DATA();
        }
    }

    // Sort and invalidate discontinuous blocks
    if (blocks.size() > 1)
    {
        std::ranges::sort(blocks, [](const Block& a, const Block& b)
        {
            return a.base < b.base;
        });

        size_t discontinuity = -1;
        for (size_t i = 0; i < blocks.size() - 1; i++)
        {
            if (blocks[i].base + blocks[i].size >= blocks[i + 1].base)
            {
                continue;
            }

            discontinuity = i + 1;
            break;
        }

        if (discontinuity != -1)
        {
            blocks.erase(blocks.begin() + discontinuity, blocks.end());
        }
    }

    fn.size = 0;
    for (const auto& block : blocks)
    {
        // pick the block furthest away
        fn.size = std::max(fn.size, block.base + block.size);
    }
    return fn;
}
