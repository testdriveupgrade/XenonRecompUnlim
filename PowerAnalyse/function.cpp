#include "function.h"
#include <disasm.h>
#include <vector>
#include <bit>

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
        const auto end = begin + size;

        if (address >= begin && address <= end)
        {
            return i;
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

    #define RESTORE_DATA() if (!blockStack.empty()) data = (dataStart + (blocks[blockStack.back()].base / sizeof(*data))) - 1; // continue adds one

    // TODO: Branch fallthrough
    for (; data <= dataEnd ; ++data)
    {
        const auto addr = base + ((data - dataStart) * sizeof(*data));
        if (blockStack.empty())
        {
            break; // it's hideover
        }

        auto& curBlock = blocks[blockStack.back()];
        const auto instruction = std::byteswap(*data);

        const auto op = PPC_OP(instruction);
        const auto xop = PPC_XOP(instruction);
        const auto isLink = instruction & 1; // call

        ppc_insn insn;
        ppc::Disassemble(data, addr, insn);

        if (curBlock.base == 0x28)
        {
            printf("");
        }

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

            curBlock.projectedSize = -1;
            blockStack.pop_back();
            // true/false paths
            // left block: false case
            // right block: true case

            const auto lBase = (addr - base) + 4;
            const auto rBase = insn.operands[1] - base;

            // these will be -1 if it's our first time seeing these blocks
            auto lBlock = fn.SearchBlock(base + lBase);

            if (lBlock == -1)
            {
                blocks.emplace_back(lBase, 0).projectedSize = rBase - lBase;
                lBlock = blocks.size() - 1;
            }

            // push this first, this gets overriden by the true case as it'd be further away
            if (lBlock != -1)
            {
                blockStack.emplace_back(lBlock);
            }

            auto rBlock = fn.SearchBlock(base + rBase);
            if (rBlock == -1)
            {
                blocks.emplace_back(insn.operands[1] - base, 0);
                rBlock = blocks.size() - 1;

                blockStack.emplace_back(rBlock);
            }

            if (!blockStack.empty())
            {
                RESTORE_DATA();
            }
        }
        else if (op == PPC_OP_B || (op == PPC_OP_CTR && xop == 16) || instruction == 0) // b, blr, end padding
        {
            if (!isLink)
            {
                blockStack.pop_back();

                // Keep analyzing if we have continuity
                if (op == PPC_OP_B)
                {
                    const auto branchBase = insn.operands[0] - base;
                    const auto branchBlock = fn.SearchBlock(insn.operands[0]);

                    // carry over our projection if blocks are next to each other
                    const auto isContinious = branchBase == curBlock.base + curBlock.size;
                    auto sizeProjection = (size_t)-1;

                    if (isContinious && curBlock.projectedSize != -1)
                    {
                        sizeProjection = curBlock.projectedSize - curBlock.size;

                        if (branchBlock == -1)
                        {
                            blocks.emplace_back(branchBase, 0, sizeProjection);
                            blockStack.emplace_back(blocks.size() - 1);
                        }
                    }
                }

                if (!blockStack.empty())
                {
                    RESTORE_DATA();
                }
            }
        }
    }
    
    for (const auto& block : blocks)
    {
        // pick the block furthest away
        fn.size = std::max(fn.size, block.base + block.size);
    }
    
    return fn;
}
