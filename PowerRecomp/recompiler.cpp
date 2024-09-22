#include "pch.h"
#include "recompiler.h"

static uint64_t ComputeMask(uint32_t mstart, uint32_t mstop)
{
    mstart &= 0x3F;
    mstop &= 0x3F;
    uint64_t value = (UINT64_MAX >> mstart) ^ ((mstop >= 63) ? 0 : UINT64_MAX >> (mstop + 1));
    return mstart <= mstop ? value : ~value;
}

void Recompiler::LoadSwitchTables(const char* filePath)
{
    toml::table toml = toml::parse_file(filePath);
    for (auto& entry : *toml["switch"].as_array())
    {
        auto& table = *entry.as_table();

        SwitchTable switchTable;
        switchTable.r = *table["r"].value<size_t>();
        for (auto& array : *table["labels"].as_array())
            switchTable.labels.push_back(*array.value<size_t>());

        switchTables.emplace(*table["base"].value<size_t>(), std::move(switchTable));
    }
}

void Recompiler::LoadExecutable(const char* filePath)
{
    const auto file = LoadFile(filePath).value();
    image = Image::ParseImage(file.data(), file.size()).value();
}

bool Recompiler::Recompile(const Function& fn, uint32_t base, const ppc_insn& insn, std::unordered_map<size_t, SwitchTable>::iterator& switchTable)
{
    println("\t// {} {}", insn.opcode->name, insn.op_str);

    auto printFunctionCall = [&](uint32_t ea)
        {
            auto targetSymbol = image.symbols.find(ea);

            if (targetSymbol != image.symbols.end() && targetSymbol->address == ea && targetSymbol->type == Symbol_Function)
            {
                println("\t{}(ctx, base);", targetSymbol->name);
            }
            else
            {
                println("\t// ERROR", ea);
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

    int id = insn.opcode->id;

    // Handling instructions that don't disassemble correctly for some reason here
    if (id == PPC_INST_VUPKHSB128 && insn.operands[2] == 0x60) id = PPC_INST_VUPKHSH128;
    else if (id == PPC_INST_VUPKLSB128 && insn.operands[2] == 0x60) id = PPC_INST_VUPKLSH128;

    switch (id)
    {
    case PPC_INST_ADD:
        println("\tctx.r{}.u64 = ctx.r{}.u64 + ctx.r{}.u64;", insn.operands[0], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_ADDI:
        print("\tctx.r{}.s64 = ", insn.operands[0]);
        if (insn.operands[1] != 0)
            print("ctx.r{}.s64 + ", insn.operands[1]);
        println("{};", static_cast<int32_t>(insn.operands[2]));
        break;

    case PPC_INST_ADDIC:
        println("\tctx.xer.ca = ctx.r{}.u32 > {};", insn.operands[1], ~insn.operands[2]);
        println("\tctx.r{}.s64 = ctx.r{}.s64 + {};", insn.operands[0], insn.operands[1], static_cast<int32_t>(insn.operands[2]));
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_ADDIS:
        print("\tctx.r{}.s64 = ", insn.operands[0]);
        if (insn.operands[1] != 0)
            print("ctx.r{}.s64 + ", insn.operands[1]);
        println("{};", static_cast<int32_t>(insn.operands[2] << 16));
        break;

    case PPC_INST_ADDZE:
        println("\ttemp.s64 = ctx.r{}.s64 + ctx.xer.ca;", insn.operands[1]);
        println("\tctx.xer.ca = temp.u32 < ctx.r{}.u32;", insn.operands[1]);
        println("\tctx.r{}.s64 = temp.s64;", insn.operands[0]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_AND:
        println("\tctx.r{}.u64 = ctx.r{}.u64 & ctx.r{}.u64;", insn.operands[0], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_ANDC:
        println("\tctx.r{}.u64 = ctx.r{}.u64 & ~ctx.r{}.u64;", insn.operands[0], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_ANDI:
        println("\tctx.r{}.u64 = ctx.r{}.u64 & {};", insn.operands[0], insn.operands[1], insn.operands[2]);
        println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_ANDIS:
        println("\tctx.r{}.u64 = ctx.r{}.u64 & {};", insn.operands[0], insn.operands[1], insn.operands[2] << 16);
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
            {
                println("\tcase {}:", i);
                auto label = switchTable->second.labels[i];
                if (label < fn.base || label >= fn.base + fn.size)
                {
                    println("\t\t// ERROR: 0x{:X}", label);
                    std::println("ERROR: Switch case at {:X} is trying to jump outside function: {:X}", base - 4, label);
                    println("\t\treturn;");
                }
                else
                {
                    println("\t\tgoto loc_{:X};", label);
                }
            }

            println("\tdefault:");
            println("\t\t__builtin_unreachable();");
            println("\t}}");

            switchTable = switchTables.end();
        }
        else
        {
            println("\tctx.fn[ctx.ctr.u32 / 4](ctx, base);");
            println("\treturn;");
        }
        break;

    case PPC_INST_BCTRL:
        println("\tctx.lr = 0x{:X};", base);
        println("\tctx.fn[ctx.ctr.u32 / 4](ctx, base);");
        break;

    case PPC_INST_BDZ:
        println("\t--ctx.ctr.u64;");
        println("\tif (ctx.ctr.u32 == 0) goto loc_{:X};", insn.operands[0]);
        break;

    case PPC_INST_BDZLR:
        println("\t--ctx.ctr.u64;");
        println("\tif (ctx.ctr.u32 == 0) return;", insn.operands[0]);
        break;

    case PPC_INST_BDNZ:
        println("\t--ctx.ctr.u64;");
        println("\tif (ctx.ctr.u32 != 0) goto loc_{:X};", insn.operands[0]);
        break;

    case PPC_INST_BDNZF:
        // NOTE: assuming eq here as a shortcut because all the instructions in the game do that
        println("\t--ctx.ctr.u64;");
        println("\tif (ctx.ctr.u32 != 0 && !ctx.cr{}.eq) goto loc_{:X};", insn.operands[0] / 4, insn.operands[1]);
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
        println("\t\tctx.fn[ctx.ctr.u32 / 4](ctx, base);");
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
        if (strchr(insn.opcode->name, '.'))
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
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_DIVW:
        println("\tctx.r{}.s32 = ctx.r{}.s32 / ctx.r{}.s32;", insn.operands[0], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_DIVWU:
        println("\tctx.r{}.u32 = ctx.r{}.u32 / ctx.r{}.u32;", insn.operands[0], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_EIEIO:
        // no op
        break;

    case PPC_INST_EXTSB:
        println("\tctx.r{}.s64 = ctx.r{}.s8;", insn.operands[0], insn.operands[1]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_EXTSH:
        println("\tctx.r{}.s64 = ctx.r{}.s16;", insn.operands[0], insn.operands[1]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_EXTSW:
        println("\tctx.r{}.s64 = ctx.r{}.s32;", insn.operands[0], insn.operands[1]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_FABS:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = fabs(ctx.f{}.f64);", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_FADD:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = ctx.f{}.f64 + ctx.f{}.f64;", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_FADDS:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = float(ctx.f{}.f64 + ctx.f{}.f64);", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_FCFID:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = double(ctx.f{}.s64);", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_FCMPU:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.cr{}.compare(ctx.f{}.f64, ctx.f{}.f64);", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_FCTID:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.s64 = _mm_cvtsd_si64(_mm_load1_pd(&ctx.f{}.f64));", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_FCTIDZ:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.s64 = _mm_cvttsd_si64(_mm_load1_pd(&ctx.f{}.f64));", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_FCTIWZ:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.s64 = _mm_cvttsd_si32(_mm_load1_pd(&ctx.f{}.f64));", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_FDIV:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = ctx.f{}.f64 / ctx.f{}.f64;", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_FDIVS:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = float(ctx.f{}.f64 / ctx.f{}.f64);", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_FMADD:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = ctx.f{}.f64 * ctx.f{}.f64 + ctx.f{}.f64;", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
        break;

    case PPC_INST_FMADDS:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = float(ctx.f{}.f64 * ctx.f{}.f64 + ctx.f{}.f64);", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
        break;

    case PPC_INST_FMR:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = ctx.f{}.f64;", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_FMSUB:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = ctx.f{}.f64 * ctx.f{}.f64 - ctx.f{}.f64;", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
        break;

    case PPC_INST_FMSUBS:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = float(ctx.f{}.f64 * ctx.f{}.f64 - ctx.f{}.f64);", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
        break;

    case PPC_INST_FMUL:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = ctx.f{}.f64 * ctx.f{}.f64;", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_FMULS:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = float(ctx.f{}.f64 * ctx.f{}.f64);", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_FNABS:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = -fabs(ctx.f{}.f64);", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_FNEG:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = -ctx.f{}.f64;", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_FNMADDS:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = float(-(ctx.f{}.f64 * ctx.f{}.f64 + ctx.f{}.f64));", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
        break;

    case PPC_INST_FNMSUB:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = -(ctx.f{}.f64 * ctx.f{}.f64 - ctx.f{}.f64);", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
        break;

    case PPC_INST_FNMSUBS:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = float(-(ctx.f{}.f64 * ctx.f{}.f64 - ctx.f{}.f64));", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
        break;

    case PPC_INST_FRES:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = 1.0f / float(ctx.f{}.f64);", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_FRSP:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = float(ctx.f{}.f64);", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_FSEL:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = ctx.f{}.f64 >= 0.0 ? ctx.f{}.f64 : ctx.f{}.f64;", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
        break;

    case PPC_INST_FSQRT:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = sqrt(ctx.f{}.f64);", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_FSQRTS:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = float(sqrt(ctx.f{}.f64));", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_FSUB:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\tctx.f{}.f64 = ctx.f{}.f64 - ctx.f{}.f64;", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_FSUBS:
        println("\tctx.fpscr.setFlushMode(false);");
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
        println("\tctx.r{}.u32 = ea;", insn.operands[2]);
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
        println("\tctx.r{}.u32 = ea;", insn.operands[2]);
        break;

    case PPC_INST_LDX:
        print("\tctx.r{}.u64 = PPC_LOAD_U64(", insn.operands[0]);
        if (insn.operands[1] != 0)
            print("ctx.r{}.u32 + ", insn.operands[1]);
        println("ctx.r{}.u32);", insn.operands[2]);
        break;

    case PPC_INST_LFD:
        println("\tctx.fpscr.setFlushMode(false);");
        print("\tctx.f{}.u64 = PPC_LOAD_U64(", insn.operands[0]);
        if (insn.operands[2] != 0)
            print("ctx.r{}.u32 + ", insn.operands[2]);
        println("{});", int32_t(insn.operands[1]));
        break;

    case PPC_INST_LFDX:
        println("\tctx.fpscr.setFlushMode(false);");
        print("\tctx.f{}.u64 = PPC_LOAD_U64(", insn.operands[0]);
        if (insn.operands[1] != 0)
            print("ctx.r{}.u32 + ", insn.operands[1]);
        println("ctx.r{}.u32);", insn.operands[2]);
        break;

    case PPC_INST_LFS:
        println("\tctx.fpscr.setFlushMode(false);");
        print("\ttemp.u32 = PPC_LOAD_U32(");
        if (insn.operands[2] != 0)
            print("ctx.r{}.u32 + ", insn.operands[2]);
        println("{});", int32_t(insn.operands[1]));
        println("\tctx.f{}.f64 = temp.f32;", insn.operands[0]);
        break;

    case PPC_INST_LFSX:
        println("\tctx.fpscr.setFlushMode(false);");
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
        print("\tctx.r{}.u64 = __builtin_bswap32(PPC_LOAD_U32(", insn.operands[0]);
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
        println("\tctx.r{}.u32 = ea;", insn.operands[2]);
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
        println("\tctx.f{}.u64 = ctx.fpscr.loadFromHost();", insn.operands[0]);
        break;

    case PPC_INST_MFLR:
        println("\tctx.r{}.u64 = ctx.lr;", insn.operands[0]);
        break;

    case PPC_INST_MFMSR:
        println("\tctx.r{}.u64 = ctx.msr;", insn.operands[0]);
        break;

    case PPC_INST_MFOCRF:
        // TODO: don't hardcode to cr6
        println("\tctx.r{}.u64 = (ctx.cr6.lt << 7) | (ctx.cr6.gt << 6) | (ctx.cr6.eq << 5) | (ctx.cr6.so << 4);", insn.operands[0]);
        break;

    case PPC_INST_MFTB:
        println("\tctx.r{}.u64 = __rdtsc();", insn.operands[0]);
        break;

    case PPC_INST_MR:
        println("\tctx.r{}.u64 = ctx.r{}.u64;", insn.operands[0], insn.operands[1]);
        if (strchr(insn.opcode->name, '.'))
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
        println("\tctx.ctr.u64 = ctx.r{}.u64;", insn.operands[0]);
        break;

    case PPC_INST_MTFSF:
        println("\tctx.fpscr.storeFromGuest(ctx.f{}.u32);", insn.operands[1]);
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
        println("\tctx.r{}.s64 = (int64_t(ctx.r{}.s32) * int64_t(ctx.r{}.s32)) >> 32;", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_MULHWU:
        println("\tctx.r{}.u64 = (uint64_t(ctx.r{}.u32) * uint64_t(ctx.r{}.u32)) >> 32;", insn.operands[0], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_MULLD:
        println("\tctx.r{}.s64 = ctx.r{}.s64 * ctx.r{}.s64;", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_MULLI:
        println("\tctx.r{}.s64 = ctx.r{}.s64 * {};", insn.operands[0], insn.operands[1], static_cast<int32_t>(insn.operands[2]));
        break;

    case PPC_INST_MULLW:
        println("\tctx.r{}.s64 = int64_t(ctx.r{}.s32) * int64_t(ctx.r{}.s32);", insn.operands[0], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_NAND:
        println("\tctx.r{}.u64 = ~(ctx.r{}.u64 & ctx.r{}.u64);", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_NEG:
        println("\tctx.r{}.s64 = -ctx.r{}.s64;", insn.operands[0], insn.operands[1]);
        if (strchr(insn.opcode->name, '.'))
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
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_OR:
        println("\tctx.r{}.u64 = ctx.r{}.u64 | ctx.r{}.u64;", insn.operands[0], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
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
        println("\tctx.r{}.u64 = _rotl64(ctx.r{}.u64, {}) & 0x{:X};", insn.operands[0], insn.operands[1], insn.operands[2], ComputeMask(insn.operands[3], 63));
        break;

    case PPC_INST_RLDICR:
        println("\tctx.r{}.u64 = _rotl64(ctx.r{}.u64, {}) & 0x{:X};", insn.operands[0], insn.operands[1], insn.operands[2], ComputeMask(0, insn.operands[3]));
        break;

    case PPC_INST_RLDIMI:
    {
        const uint64_t mask = ComputeMask(insn.operands[3], ~insn.operands[2]);
        println("\tctx.r{}.u64 = (_rotl64(ctx.r{}.u64, {}) & 0x{:X}) | (ctx.r{}.u64 & 0x{:X});", insn.operands[0], insn.operands[1], insn.operands[2], mask, insn.operands[0], ~mask);
        break;
    }

    case PPC_INST_RLWIMI:
    {
        const uint64_t mask = ComputeMask(insn.operands[3] + 32, insn.operands[4] + 32);
        println("\tctx.r{}.u64 = (_rotl(ctx.r{}.u32, {}) & 0x{:X}) | (ctx.r{}.u64 & 0x{:X});", insn.operands[0], insn.operands[1], insn.operands[2], mask, insn.operands[0], ~mask);
        break;
    }

    case PPC_INST_RLWINM:
        println("\tctx.r{}.u64 = _rotl(ctx.r{}.u32, {}) & 0x{:X};", insn.operands[0], insn.operands[1], insn.operands[2], ComputeMask(insn.operands[3] + 32, insn.operands[4] + 32));
        if (strchr(insn.opcode->name, '.'))
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
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_SLD:
        println("\tctx.r{}.u64 = ctx.r{}.u8 & 0x40 ? 0 : (ctx.r{}.u64 << (ctx.r{}.u8 & 0x7F));", insn.operands[0], insn.operands[2], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_SLW:
        println("\tctx.r{}.u64 = ctx.r{}.u8 & 0x20 ? 0 : (ctx.r{}.u32 << (ctx.r{}.u8 & 0x3F));", insn.operands[0], insn.operands[2], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_SRAD:
        println("\ttemp.u64 = ctx.r{}.u64 & 0x7F;", insn.operands[2]);
        println("\tif (temp.u64 > 0x3F) temp.u64 = 0x3F;");
        println("\tctx.xer.ca = (ctx.r{}.s64 < 0) & (((ctx.r{}.s64 >> temp.u64) << temp.u64) != ctx.r{}.s64);", insn.operands[1], insn.operands[1], insn.operands[1]);
        println("\tctx.r{}.s64 = ctx.r{}.s64 >> {};", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_SRADI:
        println("\tctx.xer.ca = (ctx.r{}.s64 < 0) & ((ctx.r{}.u64 & 0x{:X}) != 0);", insn.operands[1], insn.operands[1], ComputeMask(64 - insn.operands[2], 63));
        println("\tctx.r{}.s64 = ctx.r{}.s64 >> {};", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_SRAW:
        println("\ttemp.u32 = ctx.r{}.u32 & 0x3F;", insn.operands[2]);
        println("\tif (temp.u32 > 0x1F) temp.u32 = 0x1F;");
        println("\tctx.xer.ca = (ctx.r{}.s32 < 0) & (((ctx.r{}.s32 >> temp.u32) << temp.u32) != ctx.r{}.s32);", insn.operands[1], insn.operands[1], insn.operands[1]);
        println("\tctx.r{}.s64 = ctx.r{}.s32 >> {};", insn.operands[0], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_SRAWI:
        println("\tctx.xer.ca = (ctx.r{}.s32 < 0) & ((ctx.r{}.u32 & 0x{:X}) != 0);", insn.operands[1], insn.operands[1], ComputeMask(64 - insn.operands[2], 63));
        println("\tctx.r{}.s64 = ctx.r{}.s32 >> {};", insn.operands[0], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_SRD:
        println("\tctx.r{}.u64 = ctx.r{}.u8 & 0x40 ? 0 : (ctx.r{}.u64 >> (ctx.r{}.u8 & 0x7F));", insn.operands[0], insn.operands[2], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_SRW:
        println("\tctx.r{}.u64 = ctx.r{}.u8 & 0x20 ? 0 : (ctx.r{}.u32 >> (ctx.r{}.u8 & 0x3F));", insn.operands[0], insn.operands[2], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
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
        println("\tctx.r{}.u32 = ea;", insn.operands[2]);
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
        println("ctx.r{}.u32), __builtin_bswap64(ctx.r{}.s64), __builtin_bswap64(ctx.reserved.s64)) == __builtin_bswap64(ctx.reserved.s64);",
            insn.operands[2], insn.operands[0]);
        println("\tctx.cr0.so = ctx.xer.so;");
        break;

    case PPC_INST_STDU:
        println("\tea = {} + ctx.r{}.u32;", int32_t(insn.operands[1]), insn.operands[2]);
        println("\tPPC_STORE_U64(ea, ctx.r{}.u64);", insn.operands[0]);
        println("\tctx.r{}.u32 = ea;", insn.operands[2]);
        break;

    case PPC_INST_STDX:
        print("\tPPC_STORE_U64(");
        if (insn.operands[1] != 0)
            print("ctx.r{}.u32 + ", insn.operands[1]);
        println("ctx.r{}.u32, ctx.r{}.u64);", insn.operands[2], insn.operands[0]);
        break;

    case PPC_INST_STFD:
        println("\tctx.fpscr.setFlushMode(false);");
        print("\tPPC_STORE_U64(");
        if (insn.operands[2] != 0)
            print("ctx.r{}.u32 + ", insn.operands[2]);
        println("{}, ctx.f{}.u64);", int32_t(insn.operands[1]), insn.operands[0]);
        break;

    case PPC_INST_STFDX:
        println("\tctx.fpscr.setFlushMode(false);");
        print("\tPPC_STORE_U64(");
        if (insn.operands[1] != 0)
            print("ctx.r{}.u32 + ", insn.operands[1]);
        println("ctx.r{}.u32, ctx.f{}.u64);", insn.operands[2], insn.operands[0]);
        break;

    case PPC_INST_STFIWX:
        println("\tctx.fpscr.setFlushMode(false);");
        print("\tPPC_STORE_U32(");
        if (insn.operands[1] != 0)
            print("ctx.r{}.u32 + ", insn.operands[1]);
        println("ctx.r{}.u32, ctx.f{}.u32);", insn.operands[2], insn.operands[0]);
        break;

    case PPC_INST_STFS:
        println("\tctx.fpscr.setFlushMode(false);");
        println("\ttemp.f32 = ctx.f{}.f64;", insn.operands[0]);
        print("\tPPC_STORE_U32(");
        if (insn.operands[2] != 0)
            print("ctx.r{}.u32 + ", insn.operands[2]);
        println("{}, temp.u32);", int32_t(insn.operands[1]));
        break;

    case PPC_INST_STFSX:
        println("\tctx.fpscr.setFlushMode(false);");
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
        println("ctx.r{}.u32, __builtin_bswap16(ctx.r{}.u16));", insn.operands[2], insn.operands[0]);
        break;

    case PPC_INST_STHX:
        print("\tPPC_STORE_U16(");
        if (insn.operands[1] != 0)
            print("ctx.r{}.u32 + ", insn.operands[1]);
        println("ctx.r{}.u32, ctx.r{}.u16);", insn.operands[2], insn.operands[0]);
        break;

    case PPC_INST_STVEHX:
        // TODO: vectorize
        // NOTE: accounting for the full vector reversal here
        print("\tea = (");
        if (insn.operands[1] != 0)
            print("ctx.r{}.u32 + ", insn.operands[1]);
        println("ctx.r{}.u32) & ~0x1;", insn.operands[2]);
        println("\tPPC_STORE_U16(ea, ctx.v{}.u16[7 - ((ea & 0xF) >> 1)]);", insn.operands[0]);
        break;

    case PPC_INST_STVEWX:
    case PPC_INST_STVEWX128:
        // TODO: vectorize
        // NOTE: accounting for the full vector reversal here
        print("\tea = (");
        if (insn.operands[1] != 0)
            print("ctx.r{}.u32 + ", insn.operands[1]);
        println("ctx.r{}.u32) & ~0x3;", insn.operands[2]);
        println("\tPPC_STORE_U32(ea, ctx.v{}.u32[3 - ((ea & 0xF) >> 2)]);", insn.operands[0]);
        break;

    case PPC_INST_STVLX:
    case PPC_INST_STVLX128:
        // TODO: vectorize
        // NOTE: accounting for the full vector reversal here
        print("\tea = ");
        if (insn.operands[1] != 0)
            print("ctx.r{}.u32 + ", insn.operands[1]);
        println("ctx.r{}.u32;", insn.operands[2]);

        println("\tfor (size_t i = 0; i < (16 - (ea & 0xF)); i++)");
        println("\t\tPPC_STORE_U8(ea + i, ctx.v{}.u8[15 - i]);", insn.operands[0]);
        break;

    case PPC_INST_STVRX:
    case PPC_INST_STVRX128:
        // TODO: vectorize
        // NOTE: accounting for the full vector reversal here
        print("\tea = ");
        if (insn.operands[1] != 0)
            print("ctx.r{}.u32 + ", insn.operands[1]);
        println("ctx.r{}.u32;", insn.operands[2]);

        println("\tfor (size_t i = 0; i < (ea & 0xF); i++)");
        println("\t\tPPC_STORE_U8(ea - i - 1, ctx.v{}.u8[i]);", insn.operands[0]);
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
        println("ctx.r{}.u32, __builtin_bswap32(ctx.r{}.u32));", insn.operands[2], insn.operands[0]);
        break;

    case PPC_INST_STWCX:
        println("\tctx.cr0.lt = 0;");
        println("\tctx.cr0.gt = 0;");
        print("\tctx.cr0.eq = _InterlockedCompareExchange(reinterpret_cast<long*>(base + ");
        if (insn.operands[1] != 0)
            print("ctx.r{}.u32 + ", insn.operands[1]);
        println("ctx.r{}.u32), __builtin_bswap32(ctx.r{}.s32), __builtin_bswap32(ctx.reserved.s32)) == __builtin_bswap32(ctx.reserved.s32);",
            insn.operands[2], insn.operands[0]);
        println("\tctx.cr0.so = ctx.xer.so;");
        break;

    case PPC_INST_STWU:
        println("\tea = {} + ctx.r{}.u32;", int32_t(insn.operands[1]), insn.operands[2]);
        println("\tPPC_STORE_U32(ea, ctx.r{}.u32);", insn.operands[0]);
        println("\tctx.r{}.u32 = ea;", insn.operands[2]);
        break;

    case PPC_INST_STWUX:
        println("\tea = ctx.r{}.u32 + ctx.r{}.u32;", insn.operands[1], insn.operands[2]);
        println("\tPPC_STORE_U32(ea, ctx.r{}.u32);", insn.operands[0]);
        println("\tctx.r{}.u32 = ea;", insn.operands[1]);
        break;

    case PPC_INST_STWX:
        print("\tPPC_STORE_U32(");
        if (insn.operands[1] != 0)
            print("ctx.r{}.u32 + ", insn.operands[1]);
        println("ctx.r{}.u32, ctx.r{}.u32);", insn.operands[2], insn.operands[0]);
        break;

    case PPC_INST_SUBF:
        println("\tctx.r{}.s64 = ctx.r{}.s64 - ctx.r{}.s64;", insn.operands[0], insn.operands[2], insn.operands[1]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_SUBFC:
        println("\tctx.xer.ca = ctx.r{}.u32 >= ctx.r{}.u32;", insn.operands[2], insn.operands[1]);
        println("\tctx.r{}.s64 = ctx.r{}.s64 - ctx.r{}.s64;", insn.operands[0], insn.operands[2], insn.operands[1]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_SUBFE:
        // TODO: do we need to set the carry flag here?
        println("\tctx.r{}.u64 = ~ctx.r{}.u64 + ctx.r{}.u64 + ctx.xer.ca;", insn.operands[0], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_SUBFIC:
        println("\tctx.xer.ca = ctx.r{}.u32 <= {};", insn.operands[1], insn.operands[2]);
        println("\tctx.r{}.s64 = {} - ctx.r{}.s64;", insn.operands[0], static_cast<int32_t>(insn.operands[2]), insn.operands[1]);
        break;

    case PPC_INST_SYNC:
        // no op
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

    case PPC_INST_VADDFP:
    case PPC_INST_VADDFP128:
        println("\tctx.fpscr.setFlushMode(true);");
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
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_andnot_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[2], insn.operands[1]);
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
        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_si128((__m128i*)ctx.v{}.s32, _mm_vctsxs(_mm_mul_ps(_mm_load_ps(ctx.v{}.f32), _mm_set1_ps({}))));", insn.operands[0], insn.operands[1], 1u << insn.operands[2]);
        break;

    case PPC_INST_VCFSX:
    case PPC_INST_VCSXWFP128:
    {
        const float v = ldexp(1.0f, -int32_t(insn.operands[2]));

        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_mul_ps(_mm_cvtepi32_ps(_mm_load_si128((__m128i*)ctx.v{}.u32)), _mm_castsi128_ps(_mm_set1_epi32(int(0x{:X})))));", insn.operands[0], insn.operands[1], *reinterpret_cast<const uint32_t*>(&v));
        break;
    }

    case PPC_INST_VCFUX:
    case PPC_INST_VCUXWFP128:
    {
        const float v = ldexp(1.0f, -int32_t(insn.operands[2]));

        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_mul_ps(_mm_cvtepu32_ps_(_mm_load_si128((__m128i*)ctx.v{}.u32)), _mm_castsi128_ps(_mm_set1_epi32(int(0x{:X})))));", insn.operands[0], insn.operands[1], *reinterpret_cast<const uint32_t*>(&v));
        break;
    }

    case PPC_INST_VCMPBFP:
    case PPC_INST_VCMPBFP128:
        println("\t__debugbreak();");
        break;

    case PPC_INST_VCMPEQFP:
    case PPC_INST_VCMPEQFP128:
        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_cmpeq_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr6.setFromMask(_mm_load_ps(ctx.v{}.f32), 0xF);", insn.operands[0]);
        break;

    case PPC_INST_VCMPEQUB:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_cmpeq_epi8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr6.setFromMask(_mm_load_si128((__m128i*)ctx.v{}.u8), 0xFFFF);", insn.operands[0]);
        break;

    case PPC_INST_VCMPEQUW:
    case PPC_INST_VCMPEQUW128:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_cmpeq_epi32(_mm_load_si128((__m128i*)ctx.v{}.u32), _mm_load_si128((__m128i*)ctx.v{}.u32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr6.setFromMask(_mm_load_ps(ctx.v{}.f32), 0xF);", insn.operands[0]);
        break;

    case PPC_INST_VCMPGEFP:
    case PPC_INST_VCMPGEFP128:
        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_cmpge_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr6.setFromMask(_mm_load_ps(ctx.v{}.f32), 0xF);", insn.operands[0]);
        break;

    case PPC_INST_VCMPGTFP:
    case PPC_INST_VCMPGTFP128:
        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_cmpgt_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr6.setFromMask(_mm_load_ps(ctx.v{}.f32), 0xF);", insn.operands[0]);
        break;

    case PPC_INST_VCMPGTUB:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_cmpgt_epu8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_VCMPGTUH:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_cmpgt_epu16(_mm_load_si128((__m128i*)ctx.v{}.u16), _mm_load_si128((__m128i*)ctx.v{}.u16)));", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_VEXPTEFP:
    case PPC_INST_VEXPTEFP128:
        // TODO: vectorize
        println("\tctx.fpscr.setFlushMode(true);");
        for (size_t i = 0; i < 4; i++)
            println("\tctx.v{}.f32[{}] = exp2f(ctx.v{}.f32[{}]);", insn.operands[0], i, insn.operands[1], i);
        break;

    case PPC_INST_VLOGEFP:
    case PPC_INST_VLOGEFP128:
        // TODO: vectorize
        println("\tctx.fpscr.setFlushMode(true);");
        for (size_t i = 0; i < 4; i++)
            println("\tctx.v{}.f32[{}] = log2f(ctx.v{}.f32[{}]);", insn.operands[0], i, insn.operands[1], i);
        break;

    case PPC_INST_VMADDCFP128:
    case PPC_INST_VMADDFP:
    case PPC_INST_VMADDFP128:
        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_add_ps(_mm_mul_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
        break;

    case PPC_INST_VMAXFP:
    case PPC_INST_VMAXFP128:
        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_max_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_VMAXSW:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u32, _mm_max_epi32(_mm_load_si128((__m128i*)ctx.v{}.u32), _mm_load_si128((__m128i*)ctx.v{}.u32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_VMINFP:
    case PPC_INST_VMINFP128:
        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_min_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_VMRGHB:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_unpackhi_epi8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[2], insn.operands[1]);
        break;

    case PPC_INST_VMRGHH:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u16, _mm_unpackhi_epi16(_mm_load_si128((__m128i*)ctx.v{}.u16), _mm_load_si128((__m128i*)ctx.v{}.u16)));", insn.operands[0], insn.operands[2], insn.operands[1]);
        break;

    case PPC_INST_VMRGHW:
    case PPC_INST_VMRGHW128:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u32, _mm_unpackhi_epi32(_mm_load_si128((__m128i*)ctx.v{}.u32), _mm_load_si128((__m128i*)ctx.v{}.u32)));", insn.operands[0], insn.operands[2], insn.operands[1]);
        break;

    case PPC_INST_VMRGLB:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_unpacklo_epi8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[2], insn.operands[1]);
        break;

    case PPC_INST_VMRGLH:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u16, _mm_unpacklo_epi16(_mm_load_si128((__m128i*)ctx.v{}.u16), _mm_load_si128((__m128i*)ctx.v{}.u16)));", insn.operands[0], insn.operands[2], insn.operands[1]);
        break;

    case PPC_INST_VMRGLW:
    case PPC_INST_VMRGLW128:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u32, _mm_unpacklo_epi32(_mm_load_si128((__m128i*)ctx.v{}.u32), _mm_load_si128((__m128i*)ctx.v{}.u32)));", insn.operands[0], insn.operands[2], insn.operands[1]);
        break;

    case PPC_INST_VMSUM3FP128:
        // NOTE: accounting for full vector reversal here. should dot product yzw instead of xyz
        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_dp_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32), 0xEF));", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_VMSUM4FP128:
        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_dp_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32), 0xFF));", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_VMULFP128:
        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_mul_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_VNMSUBFP:
    case PPC_INST_VNMSUBFP128:
        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_fnmadd_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
        break;

    case PPC_INST_VOR:
    case PPC_INST_VOR128:
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_or_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_VPERM:
    case PPC_INST_VPERM128:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_perm_epi8_(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2], insn.operands[3]);
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
        // TODO: vectorize somehow?
        // NOTE: handling vector reversal here too
        println("\tctx.fpscr.setFlushMode(true);");
        switch (insn.operands[2])
        {
        case 0: // D3D color
            if (insn.operands[3] != 1 || insn.operands[4] != 3)
                std::println("Unexpected D3D color pack instruction at {:X}", base - 4);

            for (size_t i = 0; i < 4; i++)
            {
                constexpr size_t indices[] = { 3, 0, 1, 2 };
                println("\ttemp.u32 {}= uint32_t(ctx.v{}.u8[{}]) << {};", i == 0 ? "" : "|", insn.operands[1], i * 4, indices[i] * 8);
            }
            println("\tctx.v{}.u32[3] = temp.u32;", insn.operands[0]);
            break;

        default:
            println("\t__debugbreak();");
            break;
        }
        break;

    case PPC_INST_VPKSHUS:
    case PPC_INST_VPKSHUS128:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_packus_epi16(_mm_load_si128((__m128i*)ctx.v{}.s16), _mm_load_si128((__m128i*)ctx.v{}.s16)));", insn.operands[0], insn.operands[2], insn.operands[1]);
        break;

    case PPC_INST_VREFP:
    case PPC_INST_VREFP128:
        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_rcp_ps(_mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_VRFIM:
    case PPC_INST_VRFIM128:
        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_round_ps(_mm_load_ps(ctx.v{}.f32), _MM_FROUND_TO_NEG_INF | _MM_FROUND_NO_EXC));", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_VRFIN:
    case PPC_INST_VRFIN128:
        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_round_ps(_mm_load_ps(ctx.v{}.f32), _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC));", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_VRFIZ:
    case PPC_INST_VRFIZ128:
        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_round_ps(_mm_load_ps(ctx.v{}.f32), _MM_FROUND_TO_ZERO | _MM_FROUND_NO_EXC));", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_VRLIMI128:
    {
        constexpr size_t imm[] = { _MM_SHUFFLE(3, 2, 1, 0), _MM_SHUFFLE(2, 1, 0, 3), _MM_SHUFFLE(1, 0, 3, 2), _MM_SHUFFLE(0, 3, 2, 1) };
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_blend_ps(_mm_load_ps(ctx.v{}.f32), _mm_permute_ps(_mm_load_ps(ctx.v{}.f32), {}), {}));", insn.operands[0], insn.operands[0], insn.operands[1], imm[insn.operands[3]], insn.operands[2]);
        break;
    }

    case PPC_INST_VRSQRTEFP:
    case PPC_INST_VRSQRTEFP128:
        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_rsqrt_ps(_mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_VSEL:
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_or_ps(_mm_andnot_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)), _mm_and_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32))));", insn.operands[0], insn.operands[3], insn.operands[1], insn.operands[3], insn.operands[2]);
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

    case PPC_INST_VSLW:
    case PPC_INST_VSLW128:
        // TODO: vectorize, ensure endianness is correct
        for (size_t i = 0; i < 4; i++)
            println("\tctx.v{}.u32[{}] = ctx.v{}.u32[{}] << ctx.v{}.u8[{}];", insn.operands[0], i, insn.operands[1], i, insn.operands[2], i * 4);
        break;

    case PPC_INST_VSPLTB:
    {
        // NOTE: accounting for full vector reversal here
        uint32_t perm = 15 - insn.operands[2];
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_shuffle_epi8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_set1_epi8(char(0x{:X}))));", insn.operands[0], insn.operands[1], perm);
        break;
    }

    case PPC_INST_VSPLTH:
    {
        // NOTE: accounting for full vector reversal here
        uint32_t perm = 7 - insn.operands[2];
        perm = (perm * 2) | ((perm * 2 + 1) << 8);
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u16, _mm_shuffle_epi8(_mm_load_si128((__m128i*)ctx.v{}.u16), _mm_set1_epi16(short(0x{:X}))));", insn.operands[0], insn.operands[1], perm);
        break;
    }

    case PPC_INST_VSPLTISB:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_set1_epi8(char(0x{:X})));", insn.operands[0], insn.operands[1]);
        break;

    case PPC_INST_VSPLTISW:
    case PPC_INST_VSPLTISW128:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u32, _mm_set1_epi32(int(0x{:X})));", insn.operands[0], insn.operands[1]);
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
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_vsr(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_VSRAW:
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
        println("\tctx.fpscr.setFlushMode(true);");
        println("\t_mm_store_ps(ctx.v{}.f32, _mm_sub_ps(_mm_load_ps(ctx.v{}.f32), _mm_load_ps(ctx.v{}.f32)));", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_VSUBSWS:
        // TODO: vectorize
        for (size_t i = 0; i < 4; i++)
        {
            println("\ttemp.s64 = int64_t(ctx.v{}.s32[{}]) - int64_t(ctx.v{}.s32[{}]);", insn.operands[1], i, insn.operands[2], i);
            println("\tctx.v{}.s32[{}] = temp.s64 > INT_MAX ? INT_MAX : temp.s64 < INT_MIN ? INT_MIN : temp.s64;", insn.operands[0], i);
        }
        break;

    case PPC_INST_VSUBUBS:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_subs_epu8(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_VSUBUHM:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.u8, _mm_sub_epi16(_mm_load_si128((__m128i*)ctx.v{}.u8), _mm_load_si128((__m128i*)ctx.v{}.u8)));", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_VUPKD3D128:
        // TODO: vectorize somehow?
        // NOTE: handling vector reversal here too
        switch (insn.operands[2] >> 2)
        {
        case 0: // D3D color
            for (size_t i = 0; i < 4; i++)
            {
                constexpr size_t indices[] = { 3, 0, 1, 2 };
                println("\tvtemp.u32[{}] = ctx.v{}.u8[{}] | 0x3F800000;", i, insn.operands[1], indices[i]);
            }
            println("\tctx.v{} = vtemp;", insn.operands[0]);
            break;

        case 1: // 2 shorts
            for (size_t i = 0; i < 2; i++)
            {
                println("\ttemp.f32 = 3.0f;");
                println("\ttemp.s32 += ctx.v{}.s16[{}];", insn.operands[1], 1 - i);
                println("\tvtemp.f32[{}] = temp.f32;", 3 - i);
            }
            println("\tvtemp.f32[1] = 0.0f;");
            println("\tvtemp.f32[0] = 1.0f;");
            println("\tctx.v{} = vtemp;", insn.operands[0]);
            break;

        default:
            println("\t__debugbreak();");
            break;
        }
        break;

    case PPC_INST_VUPKHSB:
    case PPC_INST_VUPKHSB128:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.s16, _mm_cvtepi8_epi16(_mm_unpackhi_epi64(_mm_load_si128((__m128i*)ctx.v{}.s8), _mm_load_si128((__m128i*)ctx.v{}.s8))));", insn.operands[0], insn.operands[1], insn.operands[1]);
        break;

    case PPC_INST_VUPKHSH:
    case PPC_INST_VUPKHSH128:
        println("\t_mm_store_si128((__m128i*)ctx.v{}.s32, _mm_cvtepi16_epi32(_mm_unpackhi_epi64(_mm_load_si128((__m128i*)ctx.v{}.s16), _mm_load_si128((__m128i*)ctx.v{}.s16))));", insn.operands[0], insn.operands[1], insn.operands[1]);
        break;

    case PPC_INST_VUPKLSB:
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
        if (strchr(insn.opcode->name, '.'))
            println("\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
        break;

    case PPC_INST_XORI:
        println("\tctx.r{}.u64 = ctx.r{}.u64 ^ {};", insn.operands[0], insn.operands[1], insn.operands[2]);
        break;

    case PPC_INST_XORIS:
        println("\tctx.r{}.u64 = ctx.r{}.u64 ^ {};", insn.operands[0], insn.operands[1], insn.operands[2] << 16);
        break;

    default:
        return false;
    }

#if 1
    if (strchr(insn.opcode->name, '.'))
    {
        int lastLine = out.find_last_of('\n', out.size() - 2);
        if (out.find("ctx.cr", lastLine + 1) == std::string::npos)
            std::println("{} at {:X} has RC bit enabled but no comparison was generated", insn.opcode->name, base - 4);
    }
#endif
    
    return true;
}

bool Recompiler::Recompile(const Function& fn)
{
    auto base = fn.base;
    auto end = base + fn.size;
    auto* data = (uint32_t*)image.Find(base);

    auto symbol = image.symbols.find(fn.base);
    if (symbol != image.symbols.end())
    {
        println("PPC_FUNC({}) {{", symbol->name);
    }
    else
    {
        println("PPC_FUNC(sub_{}) {{", fn.base);
    }

    println("\tPPC_FUNC_PROLOGUE();");

    auto switchTable = switchTables.end();
    bool allRecompiled = true;

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
            println("\t// {}", insn.op_str);
#if 1
            if (*(data - 1) != 0)
                std::println("Unable to decode instruction {:X} at {:X}", *(data - 1), base - 4);
#endif
        }
        else
        {
            if (!Recompile(fn, base, insn, switchTable))
            {
                std::println("Unrecognized instruction at 0x{:X}: {}", base - 4, insn.opcode->name);
                allRecompiled = false;
            }
        }
    }

#if 0
    if (insn.opcode == nullptr || (insn.opcode->id != PPC_INST_B && insn.opcode->id != PPC_INST_BCTR && insn.opcode->id != PPC_INST_BLR))
        std::println("Function at {:X} ends prematurely with instruction {} at {:X}", fn.base, insn.opcode != nullptr ? insn.opcode->name : "INVALID", base - 4);
#endif

    println("}}\n");

    return allRecompiled;
}

void Recompiler::Recompile(const char* directoryPath)
{
    out.reserve(10 * 1024 * 1024);

    {
        println("#pragma once\n");
        println("#include <ppc_context.h>\n");

        for (auto& symbol : image.symbols)
            println("PPC_FUNC({});", symbol.name);

        SaveCurrentOutData(directoryPath, "ppc_recomp_shared.h");
    }

    {
        println("#include \"ppc_recomp_shared.h\"\n");

        println("extern \"C\" PPCFuncMapping PPCFuncMappings[] = {{");
        for (auto& symbol : image.symbols)
            println("\t{{ 0x{:X}, {} }},", symbol.address, symbol.name);

        println("\t{{ 0, nullptr }}");
        println("}};");

        SaveCurrentOutData(directoryPath, "ppc_func_mapping.cpp");
    }

    for (size_t i = 0; i < functions.size(); i++)
    {
        if ((i % 256) == 0)
        {
            SaveCurrentOutData(directoryPath);
            println("#include \"ppc_recomp_shared.h\"\n");
        }

        if ((i % 2048) == 0 || (i == (functions.size() - 1)))
            std::println("Recompiling functions... {}%", static_cast<float>(i + 1) / functions.size() * 100.0f);

        Recompile(functions[i]);
    }

    SaveCurrentOutData(directoryPath);
}

void Recompiler::SaveCurrentOutData(const char* directoryPath, const std::string_view& name)
{
    if (!out.empty())
    {
        std::string cppName;

        if (name.empty())
        {
            cppName = std::format("ppc_recomp.{}.cpp", cppFileIndex);
            ++cppFileIndex;
        }

        bool shouldWrite = true;

        // Check if an identical file already exists first to not trigger recompilation
        std::string filePath = std::format("{}/{}", directoryPath, name.empty() ? cppName : name);
        FILE* f = fopen(filePath.c_str(), "rb");
        if (f)
        {
            fseek(f, 0, SEEK_END);
            long fileSize = ftell(f);
            if (fileSize == out.size())
            {
                fseek(f, 0, SEEK_SET);
                temp.resize(fileSize);
                fread(temp.data(), 1, fileSize, f);

                shouldWrite = !XXH128_isEqual(XXH3_128bits(temp.data(), temp.size()), XXH3_128bits(out.data(), out.size()));
            }
            fclose(f);
        }

        if (shouldWrite)
        {
            f = fopen(filePath.c_str(), "wb");
            fwrite(out.data(), 1, out.size(), f);
            fclose(f);
        }

        out.clear();
    }
}
