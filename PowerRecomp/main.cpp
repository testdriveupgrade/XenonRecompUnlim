#include <file.h>
#include <image.h>
#include <function.h>
#include <format>
#include <print>
#include <disasm.h>
#include <filesystem>
#include <xbox.h>
#include <cassert>
#include <toml++/toml.hpp>
#include <unordered_map>

#define TEST_FILE "private/default.xex"

static uint64_t computeMask(uint32_t mstart, uint32_t mstop)
{
    mstart &= 0x3F;
    mstop &= 0x3F;
    uint64_t value = (UINT64_MAX >> mstart) ^ ((mstop >= 63) ? 0 : UINT64_MAX >> (mstop + 1));
    return mstart <= mstop ? value : ~value;
}

int main()
{
    const auto file = LoadFile(TEST_FILE).value();
    auto image = Image::ParseImage(file.data(), file.size()).value();

    std::println("Loading switch tables...");

    struct SwitchTable
    {
        size_t r;
        std::vector<size_t> labels;
    };

    std::unordered_map<size_t, SwitchTable> switchTables;

    toml::table toml = toml::parse_file("out/switches.toml");
    for (auto& entry : *toml["switch"].as_array())
    {
        auto& table = *entry.as_table();

        SwitchTable switchTable;
        switchTable.r = *table["r"].value<size_t>();
        for (auto& array : *table["labels"].as_array())
            switchTable.labels.push_back(*array.value<size_t>());

        switchTables.emplace(*table["base"].value<size_t>(), std::move(switchTable));
    }

    std::println("Analysing functions...");

    uint32_t cxxFrameHandler = std::byteswap(0x831B1C90);
    uint32_t cSpecificFrameHandler = std::byteswap(0x8324B3BC);
    image.symbols.emplace("__CxxFrameHandler", 0x831B1C90, 0x38, Symbol_Function);
    image.symbols.emplace("__C_specific_handler", 0x8324B3BC, 0x38, Symbol_Function);
    image.symbols.emplace("__memcpy", 0x831B0ED0, 0x488, Symbol_Function);
    image.symbols.emplace("__memset", 0x831B0BA0, 0xA0, Symbol_Function);
    image.symbols.emplace("__blkmov", 0x831B1358, 0xA8, Symbol_Function);
    image.symbols.emplace(std::format("sub_{:X}", 0x82EF5D78), 0x82EF5D78, 0x3F8, Symbol_Function);

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
                auto& missingFn = functions.emplace_back(Function::Analyze(data, dataEnd - data, base));
                image.symbols.emplace(std::format("sub_{:X}", missingFn.base), missingFn.base, missingFn.size, Symbol_Function);

                base += missingFn.size;
                data += missingFn.size;
            }
        }
    }
    
    std::string out;
    out.reserve(512 * 1024 * 1024);

    auto print = [&]<class... Args>(std::format_string<Args...> fmt, Args&&... args)
    {
        std::vformat_to(std::back_inserter(out), fmt.get(), std::make_format_args(args...));
    };

    auto println = [&]<class... Args>(std::format_string<Args...> fmt, Args&&... args)
    {
        std::vformat_to(std::back_inserter(out), fmt.get(), std::make_format_args(args...));
        out += '\n';
    };

    println("#include <ppc_context.h>\n");

    for (auto& symbol : image.symbols)
        println("PPC_FUNC void {}(PPCContext& __restrict ctx, uint8_t* base);", symbol.name);

    println("");

    for (size_t funcIdx = 0; funcIdx < functions.size(); funcIdx++)
    {
        if ((funcIdx % 1000) == 0)
            std::println("Recompiling functions... {}%", static_cast<float>(funcIdx) / functions.size() * 100.0f);

        auto& fn = functions[funcIdx];
        auto base = fn.base;
        auto end = base + fn.size;
        auto* data = (uint32_t*)image.Find(base);

        auto symbol = image.symbols.find(fn.base);
        if (symbol != image.symbols.end())
        {
            println("PPC_FUNC void {}(PPCContext& __restrict ctx, uint8_t* base) {{", symbol->name);
        }
        else
        {
            println("PPC_FUNC void sub_{:X}(PPCContext& __restrict ctx, uint8_t* base) {{", fn.base);
        }

        println("\t__assume((reinterpret_cast<size_t>(base) & 0xFFFFFFFF) == 0);");
        println("\tPPCRegister temp;");
        println("\tuint32_t ea;\n");

        auto switchTable = switchTables.end();

        ppc_insn insn;
        while (base < end)
        {
            println("loc_{:X}:", base);

            if (switchTable == switchTables.end())
                switchTable = switchTables.find(base);

            ppc::Disassemble(data, 4, base, insn);

            base += 4;
            ++data;
            if (insn.opcode == nullptr)
            {
                println("\t// {:x} {}", base - 4, insn.op_str);
            }
            else
            {
                println("\t// {:x} {} {}", base - 4, insn.opcode->name, insn.op_str);

                auto printFunctionCall = [&](uint32_t ea)
                {
                    auto targetSymbol = image.symbols.find(ea);

                    if (targetSymbol != image.symbols.end() && targetSymbol->type == Symbol_Function)
                    {
                        println("\t{}(ctx, base);", targetSymbol->name);
                    }
                    else
                    {
                        println("\tctx.fn[0x{:X}](ctx, base);", ea / 4);
                    }
                };

                auto printConditionalBranch = [&](bool not_, const std::string_view& cond)
                {
                    if (insn.operands[1] < fn.base || insn.operands[1] >= fn.base + fn.size)
                    {
                        println("\tif ({}ctx.cr{}.{}) {{", not_ ? "!" : "", insn.operands[0], cond);
                        print("\t");
                        printFunctionCall(insn.operands[1]);
                        println("\t\treturn;");
                        println("\t}}");
                    }
                    else
                    {
                        println("\tif ({}ctx.cr{}.{}) goto loc_{:X};", not_ ? "!" : "", insn.operands[0], cond, insn.operands[1]);
                    }
                };

                switch (insn.opcode->id)
                {
                case PPC_INST_ADD:
                    println("\tctx.r{}.u64 = ctx.r{}.u64 + ctx.r{}.u64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_ADDI:
                    print("\tctx.r{}.s64 = ", insn.operands[0]);
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.s64 + ", insn.operands[1]);
                    println("{};", static_cast<int32_t>(insn.operands[2]));
                    break;

                case PPC_INST_ADDIC:
                    println("\tctx.xer.ca = _addcarry_u64(0, ctx.r{}.u64, uint64_t(int64_t({})), &ctx.r{}.u64);", insn.operands[1], static_cast<int32_t>(insn.operands[2]), insn.operands[0]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_ADDIS:
                    print("\tctx.r{}.s64 = ", insn.operands[0]);
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.s64 + ", insn.operands[1]);
                    println("{};", static_cast<int32_t>(insn.operands[2] << 16));
                    break;

                case PPC_INST_ADDZE:
                    println("\tctx.xer.ca = _addcarry_u64(ctx.xer.ca, ctx.r{}.u64, 0, &ctx.r{}.u64);", insn.operands[1], insn.operands[0]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_AND:
                    println("\tctx.r{}.u64 = ctx.r{}.u64 & ctx.r{}.u64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_ANDC:
                    println("\tctx.r{}.u64 = ctx.r{}.u64 & ~ctx.r{}.u64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_ANDI:
                    println("\tctx.r{}.u64 = ctx.r{}.u64 & {};", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_ANDIS:
                    println("\tctx.r{}.u64 = ctx.r{}.u64 & {};", insn.operands[0], insn.operands[1], insn.operands[2] << 16);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_ATTN:
                    // undefined instruction
                    break;

                case PPC_INST_B:
                    if (insn.operands[0] < fn.base || insn.operands[0] >= fn.base + fn.size)
                    {
                        printFunctionCall(insn.operands[0]);
                        println("\treturn;");
                    }
                    else
                    {
                        println("\tgoto loc_{:X};", insn.operands[0]);
                    }
                    break;

                case PPC_INST_BCTR:
                    if (switchTable != switchTables.end())
                    {
                        println("\tswitch (ctx.r{}.u64) {{", switchTable->second.r);

                        for (size_t i = 0; i < switchTable->second.labels.size(); i++)
                            println("\t\tcase {}: goto loc_{:X};", i, switchTable->second.labels[i]);

                        println("\t\tdefault: __unreachable();");
                        println("\t}}");

                        switchTable = switchTables.end();
                    }
                    else
                    {
                        println("\tctx.fn[ctx.ctr / 4](ctx, base);");
                        println("\treturn;");
                    }
                    break;

                case PPC_INST_BCTRL:
                    println("\tctx.lr = 0x{:X};", base);
                    println("\tctx.fn[ctx.ctr / 4](ctx, base);");
                    break;

                case PPC_INST_BDNZ:
                    println("\tif (--ctx.ctr != 0) goto loc_{:X};", insn.operands[0]);
                    break;

                case PPC_INST_BDNZF:
                    // NOTE: assuming eq here as a shortcut because all the instructions in the game do that
                    println("\tif (--ctx.ctr != 0 && !ctx.cr{}.eq) goto loc_{:X};", insn.operands[0] / 4, insn.operands[1]);
                    break;

                case PPC_INST_BEQ:
                    printConditionalBranch(false, "eq");
                    break;

                case PPC_INST_BEQLR:
                    println("\tif (ctx.cr{}.eq) return;", insn.operands[0]);
                    break;

                case PPC_INST_BGE:
                    printConditionalBranch(true, "lt");
                    break;

                case PPC_INST_BGELR:
                    println("\tif (!ctx.cr{}.lt) return;", insn.operands[0]);
                    break;

                case PPC_INST_BGT:
                    printConditionalBranch(false, "gt");
                    break;

                case PPC_INST_BGTLR:
                    println("\tif (ctx.cr{}.gt) return;", insn.operands[0]);
                    break;

                case PPC_INST_BL:
                    println("\tctx.lr = 0x{:X};", base);
                    printFunctionCall(insn.operands[0]);
                    break;

                case PPC_INST_BLE:
                    printConditionalBranch(true, "gt");
                    break;

                case PPC_INST_BLELR:
                    println("\tif (!ctx.cr{}.gt) return;", insn.operands[0]);
                    break;

                case PPC_INST_BLR:
                    println("\treturn;");
                    break;

                case PPC_INST_BLRL:
                    println("\tctx.fn[ctx.lr / 4](ctx, base);");
                    break;

                case PPC_INST_BLT:
                    printConditionalBranch(false, "lt");
                    break;

                case PPC_INST_BLTLR:
                    println("\tif (ctx.cr{}.lt) return;", insn.operands[0]);
                    break;

                case PPC_INST_BNE:
                    printConditionalBranch(true, "eq");
                    break;

                case PPC_INST_BNECTR:
                    println("\tif (!ctx.cr{}.eq) {{", insn.operands[0]);
                    println("\t\tctx.fn[ctx.ctr / 4](ctx, base);");
                    println("\t\treturn;");
                    println("\t}}");
                    break;

                case PPC_INST_BNELR:
                    println("\tif (!ctx.cr{}.eq) return;", insn.operands[0]);
                    break;

                case PPC_INST_CCTPL:
                    // no op
                    break;

                case PPC_INST_CCTPM:
                    // no op
                    break;

                case PPC_INST_CLRLDI:
                    println("\tctx.r{}.u64 = ctx.r{}.u64 & 0x{:X};", insn.operands[0], insn.operands[1], (1ull << (64 - insn.operands[2])) - 1);
                    break;

                case PPC_INST_CLRLWI:
                    println("\tctx.r{}.u64 = ctx.r{}.u32 & 0x{:X};", insn.operands[0], insn.operands[1], (1ull << (32 - insn.operands[2])) - 1);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_CMPD:
                    println("\tctx.cr{}.compare<int64_t>(ctx.r{}.s64, ctx.r{}.s64, ctx.xer);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_CMPDI:
                    println("\tctx.cr{}.compare<int64_t>(ctx.r{}.s64, {}, ctx.xer);", insn.operands[0], insn.operands[1], int32_t(insn.operands[2]));
                    break;

                case PPC_INST_CMPLD:
                    println("\tctx.cr{}.compare<uint64_t>(ctx.r{}.u64, ctx.r{}.u64, ctx.xer);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_CMPLDI:
                    println("\tctx.cr{}.compare<uint64_t>(ctx.r{}.u64, {}, ctx.xer);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_CMPLW:
                    println("\tctx.cr{}.compare<uint32_t>(ctx.r{}.u32, ctx.r{}.u32, ctx.xer);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_CMPLWI:
                    println("\tctx.cr{}.compare<uint32_t>(ctx.r{}.u32, {}, ctx.xer);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_CMPW:
                    println("\tctx.cr{}.compare<int32_t>(ctx.r{}.s32, ctx.r{}.s32, ctx.xer);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_CMPWI:
                    println("\tctx.cr{}.compare<int32_t>(ctx.r{}.s32, {}, ctx.xer);", insn.operands[0], insn.operands[1], int32_t(insn.operands[2]));
                    break;

                case PPC_INST_CNTLZD:
                    println("\tctx.r{}.u64 = __lzcnt64(ctx.r{}.u64);", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_CNTLZW:
                    println("\tctx.r{}.u64 = __lzcnt(ctx.r{}.u32);", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_DB16CYC:
                    // no op
                    break;

                case PPC_INST_DCBF:
                    // no op
                    break;

                case PPC_INST_DCBT:
                    // no op
                    break;

                case PPC_INST_DCBTST:
                    // no op
                    break;

                case PPC_INST_DCBZ:
                    print("\tmemset(base + ((");
                    if (insn.operands[0] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[0]);
                    println("ctx.r{}.u32) & ~31), 0, 32);", insn.operands[1]);
                    break;

                case PPC_INST_DCBZL:
                    print("\tmemset(base + ((");
                    if (insn.operands[0] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[0]);
                    println("ctx.r{}.u32) & ~127), 0, 128);", insn.operands[1]);
                    break;

                case PPC_INST_DIVD:
                    println("\tctx.r{}.s64 = ctx.r{}.s64 / ctx.r{}.s64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_DIVDU:
                    println("\tctx.r{}.u64 = ctx.r{}.u64 / ctx.r{}.u64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_DIVW:
                    println("\tctx.r{}.s32 = ctx.r{}.s32 / ctx.r{}.s32;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_DIVWU:
                    println("\tctx.r{}.u32 = ctx.r{}.u32 / ctx.r{}.u32;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_EIEIO:
                    // no op
                    break;

                case PPC_INST_EXTSB:
                    println("\tctx.r{}.s64 = ctx.r{}.s8;", insn.operands[0], insn.operands[1]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_EXTSH:
                    println("\tctx.r{}.s64 = ctx.r{}.s16;", insn.operands[0], insn.operands[1]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_EXTSW:
                    println("\tctx.r{}.s64 = ctx.r{}.s32;", insn.operands[0], insn.operands[1]);
                    break;

                    // TODO: fpu operations require denormal flushing checks
                case PPC_INST_FABS:
                    println("\tctx.f{}.f64 = fabs(ctx.f{}.f64);", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_FADD:
                    println("\tctx.f{}.f64 = ctx.f{}.f64 + ctx.f{}.f64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_FADDS:
                    println("\tctx.f{}.f64 = float(ctx.f{}.f64 + ctx.f{}.f64);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_FCFID:
                    // TODO: rounding mode?
                    println("\tctx.f{}.f64 = ctx.f{}.s64;", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_FCMPU:
                    println("\tctx.cr{}.compare(ctx.f{}.f64, ctx.f{}.f64);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_FCTID:
                    // TODO: rounding mode?
                    println("\tctx.f{}.s64 = ctx.f{}.f64;", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_FCTIDZ:
                    println("\tctx.f{}.s64 = ctx.f{}.f64;", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_FCTIWZ:
                    println("\tctx.f{}.s32 = ctx.f{}.f64;", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_FDIV:
                    println("\tctx.f{}.f64 = ctx.f{}.f64 / ctx.f{}.f64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_FDIVS:
                    println("\tctx.f{}.f64 = float(ctx.f{}.f64 / ctx.f{}.f64);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_FMADD:
                    println("\tctx.f{}.f64 = ctx.f{}.f64 * ctx.f{}.f64 + ctx.f{}.f64;", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
                    break;

                case PPC_INST_FMADDS:
                    println("\tctx.f{}.f64 = float(ctx.f{}.f64 * ctx.f{}.f64 + ctx.f{}.f64);", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
                    break;

                case PPC_INST_FMR:
                    println("\tctx.f{}.f64 = ctx.f{}.f64;", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_FMSUB:
                    println("\tctx.f{}.f64 = ctx.f{}.f64 * ctx.f{}.f64 - ctx.f{}.f64;", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
                    break;

                case PPC_INST_FMSUBS:
                    println("\tctx.f{}.f64 = float(ctx.f{}.f64 * ctx.f{}.f64 - ctx.f{}.f64);", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
                    break;

                case PPC_INST_FMUL:
                    println("\tctx.f{}.f64 = ctx.f{}.f64 * ctx.f{}.f64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_FMULS:
                    println("\tctx.f{}.f64 = float(ctx.f{}.f64 * ctx.f{}.f64);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_FNABS:
                    println("\tctx.f{}.f64 = -fabs(ctx.f{}.f64);", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_FNEG:
                    println("\tctx.f{}.f64 = -ctx.f{}.f64;", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_FNMADDS:
                    println("\tctx.f{}.f64 = -float(ctx.f{}.f64 * ctx.f{}.f64 + ctx.f{}.f64);", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
                    break;

                case PPC_INST_FNMSUB:
                    println("\tctx.f{}.f64 = -(ctx.f{}.f64 * ctx.f{}.f64 - ctx.f{}.f64);", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
                    break;

                case PPC_INST_FNMSUBS:
                    println("\tctx.f{}.f64 = -float(ctx.f{}.f64 * ctx.f{}.f64 - ctx.f{}.f64);", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
                    break;

                case PPC_INST_FRES:
                    println("\tctx.f{}.f64 = 1.0 / ctx.f{}.f64;", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_FRSP:
                    println("\tctx.f{}.f64 = float(ctx.f{}.f64);", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_FSEL:
                    println("\tctx.f{}.f64 = ctx.f{}.f64 >= 0.0 ? ctx.f{}.f64 : ctx.f{}.f64;", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
                    break;

                case PPC_INST_FSQRT:
                    println("\tctx.f{}.f64 = sqrt(ctx.f{}.f64);", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_FSQRTS:
                    println("\tctx.f{}.f64 = float(sqrt(ctx.f{}.f64));", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_FSUB:
                    println("\tctx.f{}.f64 = ctx.f{}.f64 - ctx.f{}.f64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_FSUBS:
                    println("\tctx.f{}.f64 = float(ctx.f{}.f64 - ctx.f{}.f64);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_LBZ:
                    print("\tctx.r{}.u64 = PPC_LOAD_U8(", insn.operands[0]);
                    if (insn.operands[2] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[2]);
                    println("{});", int32_t(insn.operands[1]));
                    break;

                case PPC_INST_LBZU:
                    println("\tea = {} + ctx.r{}.u32;", int32_t(insn.operands[1]), insn.operands[2]);
                    println("\tctx.r{}.u64 = PPC_LOAD_U8(ea);", insn.operands[0]);
                    println("\tctx.r{}.u64 = ea;", insn.operands[2]);
                    break;

                case PPC_INST_LBZX:
                    print("\tctx.r{}.u64 = PPC_LOAD_U8(", insn.operands[0]);
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32);", insn.operands[2]);
                    break;

                case PPC_INST_LD:
                    print("\tctx.r{}.u64 = PPC_LOAD_U64(", insn.operands[0]);
                    if (insn.operands[2] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[2]);
                    println("{});", int32_t(insn.operands[1]));
                    break;

                case PPC_INST_LDARX:
                    print("\tctx.reserved.u64 = PPC_LOAD_U64(");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32);", insn.operands[2]);
                    println("\tctx.r{}.u64 = ctx.reserved.u64;", insn.operands[0]);
                    break;

                case PPC_INST_LDU:
                    println("\tea = {} + ctx.r{}.u32;", int32_t(insn.operands[1]), insn.operands[2]);
                    println("\tctx.r{}.u64 = PPC_LOAD_U64(ea);", insn.operands[0]);
                    println("\tctx.r{}.u64 = ea;", insn.operands[2]);
                    break;

                case PPC_INST_LDX:
                    print("\tctx.r{}.u64 = PPC_LOAD_U64(", insn.operands[0]);
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32);", insn.operands[2]);
                    break;

                case PPC_INST_LFD:
                    print("\tctx.f{}.u64 = PPC_LOAD_U64(", insn.operands[0]);
                    if (insn.operands[2] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[2]);
                    println("{});", int32_t(insn.operands[1]));
                    break;

                case PPC_INST_LFDX:
                    print("\tctx.f{}.u64 = PPC_LOAD_U64(", insn.operands[0]);
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32);", insn.operands[2]);
                    break;

                case PPC_INST_LFS:
                    print("\ttemp.u32 = PPC_LOAD_U32(");
                    if (insn.operands[2] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[2]);
                    println("{});", int32_t(insn.operands[1]));
                    println("\tctx.f{}.f64 = temp.f32;", insn.operands[0]);
                    break;

                case PPC_INST_LFSX:
                    print("\ttemp.u32 = PPC_LOAD_U32(");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32);", insn.operands[2]);
                    println("\tctx.f{}.f64 = temp.f32;", insn.operands[0]);
                    break;

                case PPC_INST_LHA:
                    print("\tctx.r{}.s64 = int16_t(PPC_LOAD_U16(", insn.operands[0]);
                    if (insn.operands[2] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[2]);
                    println("{}));", int32_t(insn.operands[1]));
                    break;

                case PPC_INST_LHAX:
                    print("\tctx.r{}.s64 = int16_t(PPC_LOAD_U16(", insn.operands[0]);
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32));", insn.operands[2]);
                    break;

                case PPC_INST_LHZ:
                    print("\tctx.r{}.u64 = PPC_LOAD_U16(", insn.operands[0]);
                    if (insn.operands[2] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[2]);
                    println("{});", int32_t(insn.operands[1]));
                    break;

                case PPC_INST_LHZX:
                    print("\tctx.r{}.u64 = PPC_LOAD_U16(", insn.operands[0]);
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32);", insn.operands[2]);
                    break;

                case PPC_INST_LI:
                    println("\tctx.r{}.s64 = {};", insn.operands[0], int32_t(insn.operands[1]));
                    break;

                case PPC_INST_LIS:
                    println("\tctx.r{}.s64 = {};", insn.operands[0], int32_t(insn.operands[1] << 16));
                    break;

                case PPC_INST_LVEWX:
                case PPC_INST_LVEWX128:
                case PPC_INST_LVX:
                case PPC_INST_LVX128:
                    // NOTE: for endian swapping, we reverse the whole vector instead of individual elements.
                    // this is accounted for in every instruction (eg. dp3 sums yzw instead of xyz)
                    print("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_shuffle_epi8(_mm_load_si128((__m128i*)(base + ((", insn.operands[0]);
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32) & ~0xF))), _mm_load_si128((__m128i*)VectorMaskL)));", insn.operands[2]);
                    break;

                case PPC_INST_LVLX:
                case PPC_INST_LVLX128:
                    print("\ttemp.u32 = ");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32;", insn.operands[2]);
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_shuffle_epi8(_mm_load_si128((__m128i*)(base + (temp.u32 & ~0xF))), _mm_load_si128((__m128i*)&VectorMaskL[(temp.u32 & 0xF) * 16])));", insn.operands[0]);
                    break;

                case PPC_INST_LVRX:
                case PPC_INST_LVRX128:
                    print("\ttemp.u32 = ");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32;", insn.operands[2]);
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, temp.u32 & 0xF ? _mm_shuffle_epi8(_mm_load_si128((__m128i*)(base + (temp.u32 & ~0xF))), _mm_load_si128((__m128i*)&VectorMaskR[(temp.u32 & 0xF) * 16])) : _mm_setzero_si128());", insn.operands[0]);
                    break;

                case PPC_INST_LVSL:
                    print("\ttemp.u32 = ");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32;", insn.operands[2]);
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_load_si128((__m128i*)&VectorShiftTableL[(temp.u32 & 0xF) * 16]));", insn.operands[0]);
                    break;

                case PPC_INST_LVSR:
                    print("\ttemp.u32 = ");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32;", insn.operands[2]);
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_load_si128((__m128i*)&VectorShiftTableR[(temp.u32 & 0xF) * 16]));", insn.operands[0]);
                    break;

                case PPC_INST_LWA:
                    print("\tctx.r{}.s64 = int32_t(PPC_LOAD_U32(", insn.operands[0]);
                    if (insn.operands[2] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[2]);
                    println("{}));", int32_t(insn.operands[1]));
                    break;

                case PPC_INST_LWARX:
                    print("\tctx.reserved.u32 = PPC_LOAD_U32(");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32);", insn.operands[2]);
                    println("\tctx.r{}.u64 = ctx.reserved.u32;", insn.operands[0]);
                    break;

                case PPC_INST_LWAX:
                    print("\tctx.r{}.s64 = int32_t(PPC_LOAD_U32(", insn.operands[0]);
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32));", insn.operands[2]);
                    break;

                case PPC_INST_LWBRX:
                    print("\tctx.r{}.u64 = _byteswap_ulong(PPC_LOAD_U32(", insn.operands[0]);
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32));", insn.operands[2]);
                    break;

                case PPC_INST_LWSYNC:
                    // no op
                    break;

                case PPC_INST_LWZ:
                    print("\tctx.r{}.u64 = PPC_LOAD_U32(", insn.operands[0]);
                    if (insn.operands[2] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[2]);
                    println("{});", int32_t(insn.operands[1]));
                    break;

                case PPC_INST_LWZU:
                    println("\tea = {} + ctx.r{}.u32;", int32_t(insn.operands[1]), insn.operands[2]);
                    println("\tctx.r{}.u64 = PPC_LOAD_U32(ea);", insn.operands[0]);
                    println("\tctx.r{}.u64 = ea;", insn.operands[2]);
                    break;

                case PPC_INST_LWZX:
                    print("\tctx.r{}.u64 = PPC_LOAD_U32(", insn.operands[0]);
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32);", insn.operands[2]);
                    break;

                case PPC_INST_MFCR:
                    for (size_t i = 0; i < 32; i++)
                    {
                        constexpr std::string_view fields[] = { "lt", "gt", "eq", "so" };
                        println("\tctx.r{}.u64 {}= ctx.cr{}.{} ? 0x{:X} : 0;", insn.operands[0], i == 0 ? "" : "|", i / 4, fields[i % 4], 1u << (31 - i));
                    }
                    break;

                case PPC_INST_MFFS:
                    println("\tctx.f{}.u64 = ctx.fpscr;", insn.operands[0]);
                    break;

                case PPC_INST_MFLR:
                    println("\tctx.r{}.u64 = ctx.lr;", insn.operands[0]);
                    break;

                case PPC_INST_MFMSR:
                    println("\tctx.r{}.u64 = ctx.msr;", insn.operands[0]);
                    break;

                case PPC_INST_MFOCRF:
                    println("\tctx.r{}.u64 = (ctx.cr{}.lt << 7) | (ctx.cr{}.gt << 6) | (ctx.cr{}.eq << 5) | (ctx.cr{}.so << 4);",
                        insn.operands[0], insn.operands[1], insn.operands[1], insn.operands[1], insn.operands[1]);
                    break;

                case PPC_INST_MFTB:
                    println("\tctx.r{}.u64 = __rdtsc();", insn.operands[0]);
                    break;

                case PPC_INST_MR:
                    println("\tctx.r{}.u64 = ctx.r{}.u64;", insn.operands[0], insn.operands[1]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_MTCR:
                    for (size_t i = 0; i < 32; i++)
                    {
                        constexpr std::string_view fields[] = { "lt", "gt", "eq", "so" };
                        println("\tctx.cr{}.{} = (ctx.r{}.u32 & 0x{:X}) != 0;", i / 4, fields[i % 4], insn.operands[0], 1u << (31 - i));
                    }
                    break;

                case PPC_INST_MTCTR:
                    println("\tctx.ctr = ctx.r{}.u64;", insn.operands[0]);
                    break;

                case PPC_INST_MTFSF:
                    println("\tctx.fpscr = ctx.f{}.u32;", insn.operands[1]);
                    break;

                case PPC_INST_MTLR:
                    println("\tctx.lr = ctx.r{}.u64;", insn.operands[0]);
                    break;

                case PPC_INST_MTMSRD:
                    println("\tctx.msr = (ctx.r{}.u32 & 0x8020) | (ctx.msr & ~0x8020);", insn.operands[0]);
                    break;

                case PPC_INST_MTXER:
                    println("\tctx.xer.so = (ctx.r{}.u64 & 0x80000000) != 0;", insn.operands[0]);
                    println("\tctx.xer.ov = (ctx.r{}.u64 & 0x40000000) != 0;", insn.operands[0]);
                    println("\tctx.xer.ca = (ctx.r{}.u64 & 0x20000000) != 0;", insn.operands[0]);
                    break;

                case PPC_INST_MULHW:
                    println("\tctx.r{}.s64 = int64_t(ctx.r{}.s32 * ctx.r{}.s32) << 32;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_MULHWU:
                    println("\tctx.r{}.u64 = uint64_t(ctx.r{}.u32 * ctx.r{}.u32) << 32;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_MULLD:
                    println("\tctx.r{}.s64 = ctx.r{}.s64 * ctx.r{}.s64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_MULLI:
                    println("\tctx.r{}.s64 = ctx.r{}.s64 * {};", insn.operands[0], insn.operands[1], static_cast<int32_t>(insn.operands[2]));
                    break;

                case PPC_INST_MULLW:
                    println("\tctx.r{}.s64 = ctx.r{}.s32 * ctx.r{}.s32;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_NAND:
                    println("\tctx.r{}.u64 = ~(ctx.r{}.u64 & ctx.r{}.u64);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_NEG:
                    println("\tctx.r{}.s64 = -ctx.r{}.s64;", insn.operands[0], insn.operands[1]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_NOP:
                    // no op
                    break;

                case PPC_INST_NOR:
                    println("\tctx.r{}.u64 = ~(ctx.r{}.u64 | ctx.r{}.u64);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_NOT:
                    println("\tctx.r{}.u64 = ~ctx.r{}.u64;", insn.operands[0], insn.operands[1]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_OR:
                    println("\tctx.r{}.u64 = ctx.r{}.u64 | ctx.r{}.u64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_ORC:
                    println("\tctx.r{}.u64 = ctx.r{}.u64 | ~ctx.r{}.u64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_ORI:
                    println("\tctx.r{}.u64 = ctx.r{}.u64 | {};", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_ORIS:
                    println("\tctx.r{}.u64 = ctx.r{}.u64 | {};", insn.operands[0], insn.operands[1], insn.operands[2] << 16);
                    break;

                case PPC_INST_RLDICL:
                    println("\tctx.r{}.u64 = _rotl64(ctx.r{}.u64, {}) & 0x{:X};", insn.operands[0], insn.operands[1], insn.operands[2], computeMask(insn.operands[3], 63));
                    break;

                case PPC_INST_RLDICR:
                    println("\tctx.r{}.u64 = _rotl64(ctx.r{}.u64, {}) & 0x{:X};", insn.operands[0], insn.operands[1], insn.operands[2], computeMask(0, insn.operands[3]));
                    break;

                case PPC_INST_RLDIMI:
                {
                    const uint64_t mask = computeMask(insn.operands[3], ~insn.operands[1]);
                    println("\tctx.r{}.u64 = (_rotl64(ctx.r{}.u64, {}) & 0x{:X}) | (ctx.r{}.u64 & 0x{:X});", insn.operands[0], insn.operands[1], insn.operands[2], mask, insn.operands[0], ~mask);
                    break;
                }

                case PPC_INST_RLWIMI:
                {
                    const uint64_t mask = computeMask(insn.operands[3] + 32, insn.operands[4] + 32);
                    println("\tctx.r{}.u64 = (_rotl(ctx.r{}.u32, {}) & 0x{:X}) | (ctx.r{}.u64 & 0x{:X});", insn.operands[0], insn.operands[1], insn.operands[2], mask, insn.operands[0], ~mask);
                    break;
                }

                case PPC_INST_RLWINM:
                    println("\tctx.r{}.u64 = _rotl(ctx.r{}.u32, {}) & 0x{:X};", insn.operands[0], insn.operands[1], insn.operands[2], computeMask(insn.operands[3] + 32, insn.operands[4] + 32));
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_ROTLDI:
                    println("\tctx.r{}.u64 = _rotl64(ctx.r{}.u64, {});", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_ROTLW:
                    println("\tctx.r{}.u64 = _rotl(ctx.r{}.u32, ctx.r{}.u8 & 0x1F);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_ROTLWI:
                    println("\tctx.r{}.u64 = _rotl(ctx.r{}.u32, {});", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_SLD:
                    println("\tctx.r{}.u64 = ctx.r{}.u8 & 0x40 ? 0 : ctx.r{}.u64 << (ctx.r{}.u8 & 0x7F);", insn.operands[0], insn.operands[2], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_SLW:
                    println("\tctx.r{}.u64 = ctx.r{}.u8 & 0x20 ? 0 : ctx.r{}.u32 << (ctx.r{}.u8 & 0x3F);", insn.operands[0], insn.operands[2], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_SRAD:
                    println("\ttemp.u64 = ctx.r{}.u64 & 0x7F;", insn.operands[2]);
                    println("\tif (temp.u64 > 0x3F) temp.u64 = 0x3F;");
                    println("\tctx.xer.ca = (ctx.r{}.s64 < 0) & (((ctx.r{}.s64 >> temp.u64) << temp.u64) != ctx.r{}.s64);", insn.operands[1], insn.operands[1], insn.operands[1]);
                    println("\tctx.r{}.s64 = ctx.r{}.s64 >> {};", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_SRADI:
                    println("\tctx.xer.ca = (ctx.r{}.s64 < 0) & ((ctx.r{}.u64 & 0x{:X}) != 0);", insn.operands[1], insn.operands[1], computeMask(64 - insn.operands[2], 63));
                    println("\tctx.r{}.s64 = ctx.r{}.s64 >> {};", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_SRAW:
                    println("\ttemp.u32 = ctx.r{}.u32 & 0x3F;", insn.operands[2]);
                    println("\tif (temp.u32 > 0x1F) temp.u32 = 0x1F;");
                    println("\tctx.xer.ca = (ctx.r{}.s32 < 0) & (((ctx.r{}.s32 >> temp.u32) << temp.u32) != ctx.r{}.s32);", insn.operands[1], insn.operands[1], insn.operands[1]);
                    println("\tctx.r{}.s64 = ctx.r{}.s32 >> {};", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_SRAWI:
                    println("\tctx.xer.ca = (ctx.r{}.s32 < 0) & ((ctx.r{}.u32 & 0x{:X}) != 0);", insn.operands[1], insn.operands[1], computeMask(64 - insn.operands[2], 63));
                    println("\tctx.r{}.s64 = ctx.r{}.s32 >> {};", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_SRD:
                    println("\tctx.r{}.u64 = ctx.r{}.u8 & 0x40 ? 0 : ctx.r{}.u64 >> (ctx.r{}.u8 & 0x7F);", insn.operands[0], insn.operands[2], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_SRW:
                    println("\tctx.r{}.u64 = ctx.r{}.u8 & 0x20 ? 0 : ctx.r{}.u32 >> (ctx.r{}.u8 & 0x3F);", insn.operands[0], insn.operands[2], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_STB:
                    print("\tPPC_STORE_U8(");
                    if (insn.operands[2] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[2]);
                    println("{}, ctx.r{}.u8);", int32_t(insn.operands[1]), insn.operands[0]);
                    break;

                case PPC_INST_STBU:
                    println("\tea = {} + ctx.r{}.u32;", int32_t(insn.operands[1]), insn.operands[2]);
                    println("\tPPC_STORE_U8(ea, ctx.r{}.u8);", insn.operands[0]);
                    println("\tctx.r{}.u64 = ea;", insn.operands[0]);
                    break;

                case PPC_INST_STBX:
                    print("\tPPC_STORE_U8(");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32, ctx.r{}.u8);", insn.operands[2], insn.operands[0]);
                    break;

                case PPC_INST_STD:
                    print("\tPPC_STORE_U64(");
                    if (insn.operands[2] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[2]);
                    println("{}, ctx.r{}.u64);", int32_t(insn.operands[1]), insn.operands[0]);
                    break;

                case PPC_INST_STDCX:
                    println("\tctx.cr0.lt = 0;");
                    println("\tctx.cr0.gt = 0;");
                    print("\tctx.cr0.eq = _InterlockedCompareExchange64(reinterpret_cast<__int64*>(base + ");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32), _byteswap_uint64(ctx.r{}.s64), _byteswap_uint64(ctx.reserved.s64)) == _byteswap_uint64(ctx.reserved.s64);",
                        insn.operands[2], insn.operands[0]);
                    println("\tctx.cr0.so = ctx.xer.so;");
                    break;

                case PPC_INST_STDU:
                    println("\tea = {} + ctx.r{}.u32;", int32_t(insn.operands[1]), insn.operands[2]);
                    println("\tPPC_STORE_U64(ea, ctx.r{}.u64);", insn.operands[0]);
                    println("\tctx.r{}.u64 = ea;", insn.operands[0]);
                    break;

                case PPC_INST_STDX:
                    print("\tPPC_STORE_U64(");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32, ctx.r{}.u64);", insn.operands[2], insn.operands[0]);
                    break;

                case PPC_INST_STFD:
                    print("\tPPC_STORE_U64(");
                    if (insn.operands[2] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[2]);
                    println("{}, ctx.f{}.u64);", int32_t(insn.operands[1]), insn.operands[0]);
                    break;

                case PPC_INST_STFDX:
                    print("\tPPC_STORE_U64(");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32, ctx.f{}.u64);", insn.operands[2], insn.operands[0]);
                    break;

                case PPC_INST_STFIWX:
                    print("\tPPC_STORE_U32(");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32, ctx.f{}.u32);", insn.operands[2], insn.operands[0]);
                    break;

                case PPC_INST_STFS:
                    println("\ttemp.f32 = ctx.f{}.f64;", insn.operands[0]);
                    print("\tPPC_STORE_U32(");
                    if (insn.operands[2] != 0)
                        print("ctx.r{}.u32 +", insn.operands[2]);
                    println("{}, temp.u32);", int32_t(insn.operands[1]));
                    break;

                case PPC_INST_STFSX:
                    println("\ttemp.f32 = ctx.f{}.f64;", insn.operands[0]);
                    print("\tPPC_STORE_U32(");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32, temp.u32);", insn.operands[2]);
                    break;

                case PPC_INST_STH:
                    print("\tPPC_STORE_U16(");
                    if (insn.operands[2] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[2]);
                    println("{}, ctx.r{}.u16);", int32_t(insn.operands[1]), insn.operands[0]);
                    break;

                case PPC_INST_STHBRX:
                    print("\tPPC_STORE_U16(");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32, _byteswap_ushort(ctx.r{}.u16));", insn.operands[2], insn.operands[0]);
                    break;

                case PPC_INST_STHX:
                    print("\tPPC_STORE_U16(");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32, ctx.r{}.u16);", insn.operands[2], insn.operands[0]);
                    break;

                case PPC_INST_STVEHX:
                case PPC_INST_STVEWX:
                case PPC_INST_STVEWX128:
                case PPC_INST_STVLX:
                case PPC_INST_STVLX128:
                case PPC_INST_STVRX:
                case PPC_INST_STVRX128:
                    break;

                case PPC_INST_STVX:
                case PPC_INST_STVX128:
                    print("\t_mm_store_si128((__m128i*)(base + ((");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32) & ~0xF)), _mm_shuffle_epi8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)VectorMaskL)));", insn.operands[2], insn.operands[0]);
                    break;

                case PPC_INST_STW:
                    print("\tPPC_STORE_U32(");
                    if (insn.operands[2] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[2]);
                    println("{}, ctx.r{}.u32);", int32_t(insn.operands[1]), insn.operands[0]);
                    break;

                case PPC_INST_STWBRX:
                    print("\tPPC_STORE_U32(");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32, _byteswap_ulong(ctx.r{}.u32));", insn.operands[2], insn.operands[0]);
                    break;

                case PPC_INST_STWCX:
                    println("\tctx.cr0.lt = 0;");
                    println("\tctx.cr0.gt = 0;");
                    print("\tctx.cr0.eq = _InterlockedCompareExchange(reinterpret_cast<long*>(base + ");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32), _byteswap_ulong(ctx.r{}.s32), _byteswap_ulong(ctx.reserved.s32)) == _byteswap_ulong(ctx.reserved.s32);",
                        insn.operands[2], insn.operands[0]);
                    println("\tctx.cr0.so = ctx.xer.so;");
                    break;

                case PPC_INST_STWU:
                    println("\tea = {} + ctx.r{}.u32;", int32_t(insn.operands[1]), insn.operands[2]);
                    println("\tPPC_STORE_U32(ea, ctx.r{}.u32);", insn.operands[0]);
                    println("\tctx.r{}.u64 = ea;", insn.operands[0]);
                    break;

                case PPC_INST_STWUX:
                    println("\tea = ctx.r{}.u32 + ctx.r{}.u32;", insn.operands[1], insn.operands[2]);
                    println("\tPPC_STORE_U32(ea, ctx.r{}.u32);", insn.operands[0]);
                    println("\tctx.r{}.u32 = ea;", insn.operands[0]);
                    break;

                case PPC_INST_STWX:
                    print("\tPPC_STORE_U32(");
                    if (insn.operands[1] != 0)
                        print("ctx.r{}.u32 + ", insn.operands[1]);
                    println("ctx.r{}.u32, ctx.r{}.u32);", insn.operands[2], insn.operands[0]);
                    break;

                case PPC_INST_SUBF:
                    println("\tctx.r{}.s64 = ctx.r{}.s64 - ctx.r{}.s64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_SUBFC:
                    println("\tctx.xer.ca = _subborrow_u64(0, ctx.r{}.u64, ctx.r{}.u64, &ctx.r{}.u64);", insn.operands[2], insn.operands[1], insn.operands[0]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_SUBFE:
                    println("\tctx.xer.ca = _addcarry_u64(ctx.xer.ca, ~ctx.r{}.u64, ctx.r{}.u64, &ctx.r{}.u64);", insn.operands[1], insn.operands[2], insn.operands[0]);
                    break;

                case PPC_INST_SUBFIC:
                    println("\tctx.xer.ca = _subborrow_u64(0, uint64_t(int64_t({})), ctx.r{}.u64, &ctx.r{}.u64);", static_cast<int32_t>(insn.operands[2]), insn.operands[1], insn.operands[0]);
                    break;

                case PPC_INST_SYNC:
                    // no op?
                    break;

                case PPC_INST_TDLGEI:
                    // no op
                    break;

                case PPC_INST_TDLLEI:
                    // no op
                    break;

                case PPC_INST_TWI:
                    // no op
                    break;

                case PPC_INST_TWLGEI:
                    // no op
                    break;

                case PPC_INST_TWLLEI:
                    // no op
                    break;

                    // TODO: vector instructions require denormal flushing checks
                case PPC_INST_VADDFP:
                case PPC_INST_VADDFP128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_add_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VADDSHS:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.s16, _mm_adds_epi16(_mm_load_si128((__m128i*)ctx.v{}.s16), _mm_load_si128((__m128i*)ctx.v{}.s16)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VADDUBM:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_add_epi8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VADDUBS:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_adds_epu8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VADDUHM:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u16, _mm_add_epi16(_mm_load_si128((__m128i*)ctx.v{}.u16), _mm_load_si128((__m128i*)ctx.v{}.u16)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VADDUWM:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u32, _mm_add_epi32(_mm_load_si128((__m128i*)ctx.v{}.u32), _mm_load_si128((__m128i*)ctx.v{}.u32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VADDUWS:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u32, _mm_adds_epu32(_mm_load_si128((__m128i*)ctx.v{}.u32), _mm_load_si128((__m128i*)ctx.v{}.u32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VAND:
                case PPC_INST_VAND128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_and_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VANDC128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_andnot_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VAVGSB:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_avg_epi8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VAVGSH:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_avg_epi16(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VAVGUB:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_avg_epu8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VCTSXS:
                case PPC_INST_VCFPSXWS128:
                    // TODO: saturate
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.s32, _mm_cvttps_epi32(_mm_mul_ps(_mm_load_ps(ctx.v{}.f32), _mm_set1_ps(exp2f({})))));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VCFSX:
                case PPC_INST_VCSXWFP128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_mul_ps(_mm_cvtepi32_ps(_mm_load_si128((__m128i*)ctx.v{}.u32)), _mm_set1_ps(ldexpf(1.0f, {}))));", insn.operands[0], insn.operands[1], -int32_t(insn.operands[2]));
                    break;

                case PPC_INST_VCFUX:
                case PPC_INST_VCUXWFP128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_mul_ps(_mm_cvtepu32_ps(_mm_load_si128((__m128i*)ctx.v{}.u32)), _mm_set1_ps(ldexpf(1.0f, {}))));", insn.operands[0], insn.operands[1], -int32_t(insn.operands[2]));
                    break;

                case PPC_INST_VCMPBFP128:
                    break;

                case PPC_INST_VCMPEQFP:
                case PPC_INST_VCMPEQFP128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_cmpeq_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VCMPEQUB:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_cmpeq_epi8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr6.setFromMask(_mm_load_si128((__m128i*)ctx.v{}.u8), 0xFFFF);", insn.operands[0]);
                    break;

                case PPC_INST_VCMPEQUW:
                case PPC_INST_VCMPEQUW128:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_cmpeq_epi32(_mm_load_si128((__m128i*)ctx.v{}.u32), _mm_load_si128((__m128i*)ctx.v{}.u32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if ((insn.opcode->id == PPC_INST_VCMPEQUW && (insn.opcode->opcode & 0x1)) || (insn.opcode->id == PPC_INST_VCMPEQUW128 && (insn.opcode->opcode & 0x40)))
                        println("\tctx.cr6.setFromMask(_mm_load_ps(ctx.v{}.f32), 0xF);", insn.operands[0]);
                    break;

                case PPC_INST_VCMPGEFP:
                case PPC_INST_VCMPGEFP128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_cmpge_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->id == PPC_INST_VCMPGEFP128 && (insn.opcode->opcode & 0x40))
                        println("\tctx.cr6.setFromMask(_mm_load_ps(ctx.v{}.f32), 0xF);", insn.operands[0]);
                    break;

                case PPC_INST_VCMPGTFP:
                case PPC_INST_VCMPGTFP128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_cmpgt_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->id == PPC_INST_VCMPGTFP128 && (insn.opcode->opcode & 0x40))
                        println("\tctx.cr6.setFromMask(_mm_load_ps(ctx.v{}.f32), 0xF);", insn.operands[0]);
                    break;

                case PPC_INST_VCMPGTUB:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_cmpgt_epu8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VCMPGTUH:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_cmpgt_epu16(_mm_load_si128((__m128i*)ctx.v{}.u16), _mm_load_si128((__m128i*)ctx.v{}.u16)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VEXPTEFP128:
                    // TODO: vectorize
                    for (size_t i = 0; i < 4; i++)
                        println("\tctx.v{}.f32[{}] = exp2f(ctx.v{}.f32[{}]);", insn.operands[0], i, insn.operands[1], i);
                    break;

                case PPC_INST_VLOGEFP128:
                    // TODO: vectorize
                    for (size_t i = 0; i < 4; i++)
                        println("\tctx.v{}.f32[{}] = log2f(ctx.v{}.f32[{}]);", insn.operands[0], i, insn.operands[1], i);
                    break;

                case PPC_INST_VMADDCFP128:
                    // TODO: wrong argument order
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_fmadd_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
                    break;

                case PPC_INST_VMADDFP:
                case PPC_INST_VMADDFP128:
                    // TODO: wrong argument order
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_fmadd_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
                    break;

                case PPC_INST_VMAXFP:
                case PPC_INST_VMAXFP128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_max_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VMAXSW:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u32, _mm_max_epi32(_mm_load_si128((__m128i*)ctx.v{}.u32), _mm_load_si128((__m128i*)ctx.v{}.u32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VMINFP:
                case PPC_INST_VMINFP128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_min_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VMRGHB:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_unpackhi_epi8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VMRGHH:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u16, _mm_unpackhi_epi16(_mm_load_si128((__m128i*)ctx.v{}.u16), _mm_load_si128((__m128i*)ctx.v{}.u16)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VMRGHW:
                case PPC_INST_VMRGHW128:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u32, _mm_unpackhi_epi32(_mm_load_si128((__m128i*)ctx.v{}.u32), _mm_load_si128((__m128i*)ctx.v{}.u32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VMRGLB:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_unpacklo_epi8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VMRGLH:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u16, _mm_unpacklo_epi16(_mm_load_si128((__m128i*)ctx.v{}.u16), _mm_load_si128((__m128i*)ctx.v{}.u16)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VMRGLW:
                case PPC_INST_VMRGLW128:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u32, _mm_unpacklo_epi32(_mm_load_si128((__m128i*)ctx.v{}.u32), _mm_load_si128((__m128i*)ctx.v{}.u32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VMSUM3FP128:
                    // NOTE: accounting for full vector reversal here. should dot product yzw instead of xyz
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_dp_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32), 0xEF));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VMSUM4FP128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_dp_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32), 0xFF));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VMULFP128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_mul_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VNMSUBFP:
                case PPC_INST_VNMSUBFP128:
                    // TODO: wrong argument order
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_fnmadd_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
                    break;

                case PPC_INST_VOR:
                case PPC_INST_VOR128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_or_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VPERM:
                case PPC_INST_VPERM128:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_perm_epi8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
                    break;

                case PPC_INST_VPERMWI128:
                {
                    // NOTE: accounting for full vector reversal here
                    uint32_t x = 3 - (insn.operands[2] & 0x3);
                    uint32_t y = 3 - ((insn.operands[2] >> 2) & 0x3);
                    uint32_t z = 3 - ((insn.operands[2] >> 4) & 0x3);
                    uint32_t w = 3 - ((insn.operands[2] >> 6) & 0x3);
                    uint32_t perm = x | (y << 2) | (z << 4) | (w << 6);
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u32, _mm_shuffle_epi32(_mm_load_si128((__m128i*)ctx.v{}.u32), 0x{:X}));", insn.operands[0], insn.operands[1], perm);
                    break;
                }

                case PPC_INST_VPKD3D128:
                    break;

                case PPC_INST_VPKSHUS:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_packus_epi16(_mm_load_si128((__m128i*)ctx.v{}.s16), _mm_load_si128((__m128i*)ctx.v{}.s16)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VREFP:
                case PPC_INST_VREFP128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_rcp_ps(_mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_VRFIM128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_round_ps(_mm_load_ps(ctx.v{}.f32), _MM_FROUND_TO_NEG_INF | _MM_FROUND_NO_EXC));", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_VRFIN:
                case PPC_INST_VRFIN128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_round_ps(_mm_load_ps(ctx.v{}.f32), _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC));", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_VRFIZ128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_round_ps(_mm_load_ps(ctx.v{}.f32), _MM_FROUND_TO_ZERO | _MM_FROUND_NO_EXC));", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_VRLIMI128:
                    break;

                case PPC_INST_VRSQRTEFP:
                case PPC_INST_VRSQRTEFP128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_rsqrt_ps(_mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_VSEL:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_or_ps(_mm_and_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)), _mm_andnot_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32))));", insn.operands[0], insn.operands[3], insn.operands[1], insn.operands[3], insn.operands[2]);
                    break;

                case PPC_INST_VSLB:
                    // TODO: vectorize
                    for (size_t i = 0; i < 16; i++)
                        println("\tctx.v{}.u8[{}] = ctx.v{}.u8[{}] << (ctx.v{}.u8[{}] & 0x7);", insn.operands[0], i, insn.operands[1], i, insn.operands[2], i);
                    break;

                case PPC_INST_VSLDOI:
                case PPC_INST_VSLDOI128:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_alignr_epi8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8), {}));", insn.operands[0], insn.operands[1], insn.operands[2], 16 - insn.operands[3]);
                    break;

                case PPC_INST_VSLW128:
                    // TODO: vectorize, ensure endianness is correct
                    for (size_t i = 0; i < 4; i++)
                        println("\tctx.v{}.u32[{}] = ctx.v{}.u32[{}] << ctx.v{}.u8[{}];", insn.operands[0], i, insn.operands[1], i, insn.operands[2], i * 4);
                    break;

                case PPC_INST_VSPLTH:
                {
                    // NOTE: accounting for full vector reversal here
                    uint32_t perm = 7 - insn.operands[2];
                    perm = (perm * 2) | ((perm * 2 + 1) << 8);
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u16, _mm_shuffle_epi8(_mm_load_si128((__m128i*)ctx.v{}.u16), _mm_set1_epi16(0x{:X})));", insn.operands[0], insn.operands[1], perm);
                    break;
                }

                case PPC_INST_VSPLTISB:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_set1_epi8(0x{:X}));", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_VSPLTISW:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u32, _mm_set1_epi32(0x{:X}));", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_VSPLTISW128:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u32, _mm_set1_epi32(0x{:X}));", insn.operands[0], insn.operands[2]);
                    break;

                case PPC_INST_VSPLTW:
                case PPC_INST_VSPLTW128:
                {
                    // NOTE: accounting for full vector reversal here
                    uint32_t perm = 3 - insn.operands[2];
                    perm |= (perm << 2) | (perm << 4) | (perm << 6);
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u32, _mm_shuffle_epi32(_mm_load_si128((__m128i*)ctx.v{}.u32), 0x{:X}));", insn.operands[0], insn.operands[1], perm);
                    break;
                }

                case PPC_INST_VSR:
                    break;

                case PPC_INST_VSRAW128:
                    // TODO: vectorize, ensure endianness is correct
                    for (size_t i = 0; i < 4; i++)
                        println("\tctx.v{}.s32[{}] = ctx.v{}.s32[{}] >> ctx.v{}.u8[{}];", insn.operands[0], i, insn.operands[1], i, insn.operands[2], i * 4);
                    break;

                case PPC_INST_VSRW:
                case PPC_INST_VSRW128:
                    // TODO: vectorize, ensure endianness is correct
                    for (size_t i = 0; i < 4; i++)
                        println("\tctx.v{}.u32[{}] = ctx.v{}.u32[{}] >> ctx.v{}.u8[{}];", insn.operands[0], i, insn.operands[1], i, insn.operands[2], i * 4);
                    break;

                case PPC_INST_VSUBFP:
                case PPC_INST_VSUBFP128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_sub_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VSUBSWS:
                    break;

                case PPC_INST_VSUBUBS:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_subs_epu8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VSUBUHM:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_sub_epi16(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_VUPKD3D128:
                    break;

                case PPC_INST_VUPKHSB128:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.s16, _mm_cvtepi8_epi16(_mm_unpackhi_epi64(_mm_load_si128((__m128i*)ctx.v{}.s8), _mm_load_si128((__m128i*)ctx.v{}.s8))));", insn.operands[0], insn.operands[1], insn.operands[1]);
                    break;

                case PPC_INST_VUPKHSH:
                case PPC_INST_VUPKHSH128:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.s32, _mm_cvtepi16_epi32(_mm_unpackhi_epi64(_mm_load_si128((__m128i*)ctx.v{}.s16), _mm_load_si128((__m128i*)ctx.v{}.s16))));", insn.operands[0], insn.operands[1], insn.operands[1]);
                    break;

                case PPC_INST_VUPKLSB128:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.s32, _mm_cvtepi8_epi16(_mm_load_si128((__m128i*)ctx.v{}.s16)));", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_VUPKLSH:
                case PPC_INST_VUPKLSH128:
                    println("\t_mm_store_si128((__m128i*)ctx.v{}.s32, _mm_cvtepi16_epi32(_mm_load_si128((__m128i*)ctx.v{}.s16)));", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_VXOR:
                case PPC_INST_VXOR128:
                    println("\t_mm_store_ps(ctx.v{}.f32, _mm_xor_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_XOR:
                    println("\tctx.r{}.u64 = ctx.r{}.u64 ^ ctx.r{}.u64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_XORI:
                    println("\tctx.r{}.u64 = ctx.r{}.u64 ^ {};", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_XORIS:
                    println("\tctx.r{}.u64 = ctx.r{}.u64 ^ {};", insn.operands[0], insn.operands[1], insn.operands[2] << 16);
                    break;
                }
            }
        }

        println("}}\n");
    }

    std::filesystem::create_directory("out");

    FILE* f = fopen("out/" TEST_FILE ".cpp", "w");
    fwrite(out.data(), 1, out.size(), f);
    fclose(f);

    return 0;
}
