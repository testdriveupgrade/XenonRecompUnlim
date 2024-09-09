#include <cassert>
#include <file.h>
#include <disasm.h>
#include <image.h>
#include "function.h"
#include <print>

int main()
{
    const auto file = LoadFile("cond-fall.elf").value();
    auto image = Image::ParseImage(file.data(), file.size()).value();

    for (const auto& section : image.sections)
    {
        image.symbols.emplace(section.name, section.base, section.size, Symbol_Section);
    }

    //ppc_insn insn;
    //uint8_t c[4] = { 0x10, 0x00, 0x59, 0xC3 };
    //ppc::Disassemble(c, 0x831D6C64, insn);
    //std::println("{:20}{}", insn.opcode->name, insn.op_str);

    std::vector<Function> functions;
    for (const auto& section : image.sections)
    {
        if (!(section.flags & SectionFlags_Code))
        {
            continue;
        }

        size_t base = section.base;
        uint8_t* data = section.data;
        uint8_t* dataEnd = section.data + section.size;
        while (data < dataEnd)
        {
            if (*(uint32_t*)data == 0)
            {
                data += 4;
                base += 4;
                continue;
            }

            const auto& fn = functions.emplace_back(Function::Analyze(data, dataEnd - data, base));
            data += fn.size;
            base += fn.size;

            image.symbols.emplace(std::format("sub_{:X}", fn.base), fn.base, fn.size, Symbol_Function);
        }
    }

    const auto entrySymbol = image.symbols.find(image.entry_point);
    assert(entrySymbol != image.symbols.end());

    const auto entrySize = entrySymbol->size;
    image.symbols.erase(entrySymbol);

    image.symbols.emplace("_start", image.entry_point, entrySize, Symbol_Function);

    std::println("FUNCTIONS");
    for (const auto& fn : functions)
    {
        std::println("\tsub_{:X}", fn.base);
    }
    std::println("");
    

    std::println("SECTIONS");
    for (const auto& section : image.sections)
    {
        std::printf("Section %.8s\n", section.name.c_str());
        std::printf("\t%X-%X\n", section.base, section.base + section.size);
    }

    std::println("");
    return 0;
}
