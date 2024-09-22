#include "pch.h"
#include "swa_recompiler.h"

void SWARecompiler::Analyse()
{
    constexpr uint32_t cxxFrameHandler = std::byteswap(0x831B1C90);
    constexpr uint32_t cSpecificFrameHandler = std::byteswap(0x8324B3BC);
    constexpr uint32_t yetAnotherFrameHandler = std::byteswap(0x831C8B50);

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

    for (size_t i = 15; i < 128; i++)
    {
        if (i < 32)
        {
            auto& restgpr = functions.emplace_back();
            restgpr.base = 0x831B0B40 + (i - 14) * 4;
            restgpr.size = 0x831B0B94 - restgpr.base;
            image.symbols.emplace(std::format("__restgprlr_{}", i), restgpr.base, restgpr.size, Symbol_Function);

            auto& savegpr = functions.emplace_back();
            savegpr.base = 0x831B0AF0 + (i - 14) * 4;
            savegpr.size = 0x831B0B40 - savegpr.base;
            image.symbols.emplace(std::format("__savegprlr_{}", i), savegpr.base, savegpr.size, Symbol_Function);

            auto& restfpr = functions.emplace_back();
            restfpr.base = 0x831B144C + (i - 14) * 4;
            restfpr.size = 0x831B1498 - restfpr.base;
            image.symbols.emplace(std::format("__restfpr_{}", i), restfpr.base, restfpr.size, Symbol_Function);

            auto& savefpr = functions.emplace_back();
            savefpr.base = 0x831B1400 + (i - 14) * 4;
            savefpr.size = 0x831B144C - savefpr.base;
            image.symbols.emplace(std::format("__savefpr_{}", i), savefpr.base, savefpr.size, Symbol_Function);

            auto& restvmx = functions.emplace_back();
            restvmx.base = 0x831B36E8 + (i - 14) * 8;
            restvmx.size = 0x831B377C - restvmx.base;
            image.symbols.emplace(std::format("__restvmx_{}", i), restvmx.base, restvmx.size, Symbol_Function);

            auto& savevmx = functions.emplace_back();
            savevmx.base = 0x831B3450 + (i - 14) * 8;
            savevmx.size = 0x831B34E4 - savevmx.base;
            image.symbols.emplace(std::format("__savevmx_{}", i), savevmx.base, savevmx.size, Symbol_Function);
        }

        if (i >= 64)
        {
            auto& restvmx = functions.emplace_back();
            restvmx.base = 0x831B377C + (i - 64) * 8;
            restvmx.size = 0x831B3980 - restvmx.base;
            image.symbols.emplace(std::format("__restvmx_{}", i), restvmx.base, restvmx.size, Symbol_Function);

            auto& savevmx = functions.emplace_back();
            savevmx.base = 0x831B34E4 + (i - 64) * 8;
            savevmx.size = 0x831B36E8 - savevmx.base;
            image.symbols.emplace(std::format("__savevmx_{}", i), savevmx.base, savevmx.size, Symbol_Function);
        }
    }

    auto hardcodedFuncCheck = [&](Function& f)
        {
            if (f.base == 0x824E7EF0) f.size = 0x98;
            else if (f.base == 0x824E7F28) f.size = 0x60;
            else if (f.base == 0x82C980E8) f.size = 0x110;
            else if (f.base == 0x82CF7080) f.size = 0x80;
            else if (f.base == 0x82D9AC08) f.size = 0x78;
            else if (f.base == 0x82E86770) f.size = 0x98;
            else if (f.base == 0x82E97E50) f.size = 0x84;
            else if (f.base == 0x82EE2D08) f.size = 0x154;
            else if (f.base == 0x82EF5C38) f.size = 0x64;
            else if (f.base == 0x82EF5D78) f.size = 0x3F8;
            else if (f.base == 0x82F08730) f.size = 0x2B0;
            else if (f.base == 0x82F098C0) f.size = 0x19C;
            else if (f.base == 0x82F13980) f.size = 0xF4;
            else if (f.base == 0x82F1D668) f.size = 0x1E8;
            else if (f.base == 0x82F22908) f.size = 0x20C;
            else if (f.base == 0x82F25FD8) f.size = 0x240;
            else if (f.base == 0x82F852A0) f.size = 0xCC;
            else if (f.base == 0x830DADA0) f.size = 0x150;
            else if (f.base == 0x831487D0) f.size = 0xD4;
            else if (f.base == 0x831530C8) f.size = 0x258;
            else if (f.base == 0x831539E0) f.size = 0xD0;
            else if (f.base == 0x83168940) f.size = 0x100;
            else if (f.base == 0x83168A48) f.size = 0x11C;
            else if (f.base == 0x83168B70) f.size = 0x128;
            else if (f.base == 0x83168F18) f.size = 0x254;
            else if (f.base == 0x8316C678) f.size = 0x78;
            else if (f.base == 0x8317CD30) f.size = 0x50;
            else if (f.base == 0x83180700) f.size = 0x74;
            else if (f.base == 0x8319ED58) f.size = 0x98;
            else if (f.base == 0x82455E70) f.size = 0x84;
            else if (f.base == 0x82456DC8) f.size = 0xD4;
            else if (f.base == 0x826ABB70) f.size = 0x70;
            else if (f.base == 0x82893088) f.size = 0x45C;
            else if (f.base == 0x82C49540) f.size = 0x114;
            else if (f.base == 0x82DE35D8) f.size = 0x68;
            else if (f.base == 0x82DE3640) f.size = 0x64;
            else if (f.base == 0x82DE36A8) f.size = 0x5C;
            else if (f.base == 0x82DE3708) f.size = 0x198;
            else if (f.base == 0x82DE38A0) f.size = 0x16C;
            else if (f.base == 0x830B7DD0) f.size = 0x74;
            else if (f.base == 0x831B0BA0) f.size = 0xA0;
            else if (f.base == 0x8305D168) f.size = 0x278;
        };

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
            uint32_t insn = std::byteswap(*(uint32_t*)data);
            if (PPC_OP(insn) == PPC_OP_B && PPC_BL(insn))
            {
                size_t address = base + (data - section.data) + PPC_BI(insn);

                if (address >= section.base && address < section.base + section.size && image.symbols.find(address) == image.symbols.end())
                {
                    auto& fn = functions.emplace_back(Function::Analyze(section.data + address - section.base, section.base + section.size - address, address));
                    hardcodedFuncCheck(fn);
                    image.symbols.emplace(std::format("sub_{:X}", fn.base), fn.base, fn.size, Symbol_Function);
                }
            }
            data += 4;
        }

        data = section.data;

        while (data < dataEnd)
        {
            if (*(uint32_t*)data == 0)
            {
                data += 4;
                base += 4;
                continue;
            }

            if (*(uint32_t*)data == cxxFrameHandler || *(uint32_t*)data == cSpecificFrameHandler || *(uint32_t*)data == yetAnotherFrameHandler)
            {
                data += 8;
                base += 8;
                continue;
            }

            auto fnSymbol = image.symbols.find(base);
            if (fnSymbol != image.symbols.end() && fnSymbol->address == base && fnSymbol->type == Symbol_Function)
            {
                assert(fnSymbol->address == base);

                base += fnSymbol->size;
                data += fnSymbol->size;
            }
            else
            {
                auto& fn = functions.emplace_back(Function::Analyze(data, dataEnd - data, base));
                hardcodedFuncCheck(fn);
                image.symbols.emplace(std::format("sub_{:X}", fn.base), fn.base, fn.size, Symbol_Function);

                base += fn.size;
                data += fn.size;
            }
        }
    }

    std::sort(functions.begin(), functions.end(), [](auto& lhs, auto& rhs) { return lhs.base < rhs.base; });
}
