#include <cassert>
#include <file.h>
#include <disasm.h>
#include <image.h>
#include "function.h"
#include <print>
#include <xbox.h>

int main()
{
    const auto file = LoadFile("private/default.xex").value();
    auto image = Image::ParseImage(file.data(), file.size()).value();

    //for (const auto& section : image.sections)
    //{
    //    image.symbols.emplace(section.name, section.base, section.size, Symbol_Section);
    //}

    uint32_t cxxFrameHandler = std::byteswap(0x831B1C90);
    uint32_t cSpecificFrameHandler = std::byteswap(0x8324B3BC);
    image.symbols.emplace("__CxxFrameHandler", 0x831B1C90, 0x38, Symbol_Function);
    image.symbols.emplace("__C_specific_handler", 0x82BD7780, 0x38, Symbol_Function);
    image.symbols.emplace("memcpy", 0x831B0ED0, 0x488, Symbol_Function);
    image.symbols.emplace("memset", 0x831B0BA0, 0xA0, Symbol_Function);
    image.symbols.emplace("blkmov", 0x831B1358, 0xA8, Symbol_Function);

    image.symbols.emplace(std::format("sub_{:X}", 0x82EF5D78), 0x82EF5D78, 0x3F8, Symbol_Function);

    auto fnd = Function::Analyze(image.Find(0x831B1358), image.size, 0x831B1358);

    std::vector<Function> functions;
    auto& pdata = *image.Find(".pdata");
    size_t count = pdata.size / sizeof(IMAGE_CE_RUNTIME_FUNCTION);
    auto* pf = (IMAGE_CE_RUNTIME_FUNCTION*)pdata.data;
    for (size_t i = 0; i < count; i++)
    {
        auto fn = pf[i];
        fn.BeginAddress = std::byteswap(fn.BeginAddress);
        fn.Data = std::byteswap(fn.Data);

        auto& f = functions.emplace_back();
        f.base = fn.BeginAddress;
        f.size = fn.FunctionLength * 4;

        image.symbols.emplace(std::format("sub_{:X}", f.base), f.base, f.size, Symbol_Function);
    }

    // auto sym = image.symbols.find(0x822C0000);

    std::vector<Function> missingFunctions;
    for (const auto& section : image.sections) 
    {
        if (!(section.flags & SectionFlags_Code))
        {
            continue;
        }
        size_t base = section.base;
        uint8_t* data = section.data;
        uint8_t* dataEnd = section.data + section.size;
        const Symbol* prevSymbol = nullptr;
        while (data < dataEnd)
        {
            if (*(uint32_t*)data == 0)
            {
                data += 4;
                base += 4;
                continue;
            }

            if (*(uint32_t*)data == cxxFrameHandler || *(uint32_t*)data == cSpecificFrameHandler)
            {
                data += 8;
                base += 8;
                continue;
            }

            auto fnSymbol = image.symbols.find(base);
            if (fnSymbol != image.symbols.end() && fnSymbol->type == Symbol_Function)
            {
                assert(fnSymbol->address == base);

                prevSymbol = &*fnSymbol;
                base += fnSymbol->size;
                data += fnSymbol->size;
            }
            else
            {
                auto& missingFn = missingFunctions.emplace_back(Function::Analyze(data, dataEnd - data, base));
                base += missingFn.size;
                data += missingFn.size;
                
                std::println("sub_{:X}", missingFn.base);
            }
        }
    }

    //ppc_insn insn;
    //uint8_t c[4] = { 0x10, 0x00, 0x59, 0xC3 };
    //ppc::Disassemble(c, 0x831D6C64, insn);
    //std::println("{:20}{}", insn.opcode->name, insn.op_str);
    //for (const auto& section : image.sections)
    //{
    //    if (!(section.flags & SectionFlags_Code))
    //    {
    //        continue;
    //    }

    //    size_t base = section.base;
    //    uint8_t* data = section.data;
    //    uint8_t* dataEnd = section.data + section.size;
    //    while (data < dataEnd)
    //    {
    //        if (*(uint32_t*)data == 0)
    //        {
    //            data += 4;
    //            base += 4;
    //            continue;
    //        }

    //        const auto& fn = functions.emplace_back(Function::Analyze(data, dataEnd - data, base));
    //        data += fn.size;
    //        base += fn.size;

    //        image.symbols.emplace(std::format("sub_{:X}", fn.base), fn.base, fn.size, Symbol_Function);
    //    }
    //}

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
