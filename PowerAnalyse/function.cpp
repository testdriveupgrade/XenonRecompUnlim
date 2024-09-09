#include "function.h"
#include <disasm.h>
#include <vector>
#include <bit>

size_t function::SearchBlock(size_t address) const
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

function function::Analyze(const void* code, size_t size, size_t base)
{
    function fn{ base, 0 };
    auto& blocks = fn.blocks;
    blocks.emplace_back();

    const auto* data = (uint32_t*)code;
    const auto* dataStart = data;
    const auto* dataEnd = (uint32_t*)((uint8_t*)code + size);
    std::vector<size_t> blockStack{};
    blockStack.emplace_back();

    // TODO: Branch fallthrough
    for (; data <= dataEnd ; ++data)
    {
        const auto addr = base + ((data - dataStart) * sizeof(*data));
        if (blockStack.empty())
        {
            break; // it's hideover
        }

        const auto instruction = std::byteswap(*data);

        const auto op = PPC_OP(instruction);
        const auto xop = PPC_XOP(instruction);
        const auto isLink = instruction & 1; // call

        ppc_insn insn;
        ppc::Disassemble(data, addr, insn);

        blocks[blockStack.back()].size += 4;
        if (op == PPC_OP_BC) // conditional branches all originate from one opcode, thanks RISC
        {
            // this one ends here
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
                blocks.emplace_back(lBase, 0);
                lBlock = blocks.size() - 1;
            }

            // push this first, this gets overriden by the true case as it'd be further away
            if (lBlock != -1)
            {
                blockStack.emplace_back(lBlock);
            }

            if (!isLink) // not a call, scan this too
            {
                auto rBlock = fn.SearchBlock(base + rBase);
                if (rBlock == -1)
                {
                    blocks.emplace_back(insn.operands[1] - base, 0);
                    rBlock = blocks.size() - 1;

                    blockStack.emplace_back(rBlock);
                }
            }

            if (!blockStack.empty())
            {
                data = (dataStart + (blocks[blockStack.back()].base / sizeof(*data))) - 1; // loop will add one
            }
        }
        else if (op == PPC_OP_B || (op == PPC_OP_CTR && xop == 16) || instruction == 0) // b, blr, end padding
        {
            if (!isLink)
            {
                blockStack.pop_back();

                // single block with a branch means it'd be a tail call
                // we don't have to analyze the target in that case
                if (op == PPC_OP_B && blocks.size() != 1)
                {
                    const auto branchBase = insn.operands[0] - base;
                    const auto branchBlock = fn.SearchBlock(insn.operands[0]);

                    if (branchBlock == -1)
                    {
                        blocks.emplace_back(branchBase, 0);
                        blockStack.emplace_back(blocks.size() - 1);
                    }
                }

                if (!blockStack.empty())
                {
                    data = (dataStart + (blocks[blockStack.back()].base / sizeof(*data))) - 1;
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
