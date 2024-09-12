#include <file.h>
#include <image.h>
#include <function.h>
#include <format>
#include <print>
#include <disasm.h>
#include <filesystem>

#define TEST_FILE "add-cond.elf"

int main()
{
    const auto file = LoadFile(TEST_FILE).value();
    auto image = Image::ParseImage(file.data(), file.size()).value();

    // TODO: Load functions from an existing database
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

    std::filesystem::create_directory("out");
    FILE* f = fopen("out/" TEST_FILE ".cpp", "w");
    std::println(f, "#include <ppc_context.h>\n");

    for (const auto& fn : functions)
    {
        auto base = fn.base;
        auto end = base + fn.size;
        auto* data = (uint32_t*)image.Find(base);

        std::string name = "";
        auto symbol = image.symbols.find(base);
        if (symbol != image.symbols.end())
        {
            name = symbol->name;
        }
        else
        {
            name = std::format("sub_{:X}", base);
        }

        std::println(f, "PPC_FUNC void {}(PPCContext& __restrict ctx, uint8_t* base) {{", name);
        std::println(f, "\tuint32_t ea;\n");

        ppc_insn insn;
        while (base < end)
        {
            std::println(f, "loc_{:X}:", base);

            ppc::Disassemble(data, 4, base, insn);

            base += 4;
            ++data;
            if (insn.opcode == nullptr)
            {
                std::println(f, "\t// {:x} {}", base - 4, insn.op_str);
            }
            else
            {
                std::println(f, "\t// {:x} {} {}", base - 4, insn.opcode->name, insn.op_str);
                switch (insn.opcode->id)
                {
                case PPC_INST_ADD:
                    std::println(f, "\tctx.r{}.u64 = ctx.r{}.u64 + ctx.r{}.u64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        std::println(f, "\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_ADDI:
                    std::println(f, "\tctx.r{}.s64 = ctx.r{}.s64 + {};", insn.operands[0], insn.operands[1], static_cast<int32_t>(insn.operands[2]));
                    break;

                case PPC_INST_ADDIC:
                    break;

                case PPC_INST_ADDIS:
                    std::println(f, "\tctx.r{}.s64 = ctx.r{}.s64 + {};", insn.operands[0], insn.operands[1], static_cast<int32_t>(insn.operands[2] << 16));
                    break;

                case PPC_INST_ADDZE:
                    break;

                case PPC_INST_AND:
                    std::println(f, "\tctx.r{}.u64 = ctx.r{}.u64 & ctx.r{}.u64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        std::println(f, "\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_ANDC:
                    std::println(f, "\tctx.r{}.u64 = ctx.r{}.u64 & ~ctx.r{}.u64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        std::println(f, "\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_ANDI:
                    std::println(f, "\tctx.r{}.u64 = ctx.r{}.u64 & {};", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        std::println(f, "\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_ANDIS:
                    std::println(f, "\tctx.r{}.u64 = ctx.r{}.u64 & {};", insn.operands[0], insn.operands[1], insn.operands[2] << 16);
                    if (insn.opcode->opcode & 0x1)
                        std::println(f, "\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_ATTN:
                    // undefined instruction
                    break;

                case PPC_INST_B:
                    // TODO: tail calls
                    std::println(f, "\tgoto loc_{:X};", insn.operands[0]);
                    break;

                case PPC_INST_BCTR:
                case PPC_INST_BCTRL:
                    break;

                case PPC_INST_BDNZ:
                    std::println(f, "\tif (--ctx.ctr != 0) goto loc_{:X};", insn.operands[0]);
                    break;

                case PPC_INST_BDNZF:
                    break;

                case PPC_INST_BEQ:
                    std::println(f, "\tif (ctx.cr{}.eq) goto loc_{:X};", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_BEQLR:
                    std::println(f, "\tif (ctx.cr{}.eq) return;", insn.operands[0]);
                    break;

                case PPC_INST_BGE:
                    std::println(f, "\tif (!ctx.cr{}.lt) goto loc_{:X};", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_BGELR:
                    std::println(f, "\tif (!ctx.cr{}.lt) return;", insn.operands[0]);
                    break;

                case PPC_INST_BGT:
                    std::println(f, "\tif (ctx.cr{}.gt) goto loc_{:X};", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_BGTLR:
                    std::println(f, "\tif (ctx.cr{}.gt) return;", insn.operands[0]);
                    break;

                case PPC_INST_BL:
                {
                    std::string targetName = "";
                    auto targetSymbol = image.symbols.find(insn.operands[0]);
                    if (targetSymbol != image.symbols.end() && targetSymbol->type == Symbol_Function)
                    {
                        targetName = targetSymbol->name;
                    }
                    else
                    {
                        targetName = std::format("sub_{:X}", insn.operands[0]);
                    }
                    std::println(f, "\tctx.lr = 0x{:X};", base);
                    std::println(f, "\t{}(ctx, base);", targetName);
                    break;
                }

                case PPC_INST_BLE:
                    std::println(f, "\tif (!ctx.cr{}.gt) goto loc_{:X};", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_BLELR:
                    std::println(f, "\tif (!ctx.cr{}.gt) return;", insn.operands[0]);
                    break;

                case PPC_INST_BLR:
                    std::println(f, "\treturn;");
                    break;

                case PPC_INST_BLRL:
                    break;

                case PPC_INST_BLT:
                    std::println(f, "\tif (ctx.cr{}.lt) goto loc_{:X};", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_BLTLR:
                    std::println(f, "\tif (ctx.cr{}.lt) return;", insn.operands[0]);
                    break;

                case PPC_INST_BNE:
                    std::println(f, "\tif (!ctx.cr{}.eq) goto loc_{:X};", insn.operands[0], insn.operands[1]);
                    break;

                case PPC_INST_BNECTR:
                    break;

                case PPC_INST_BNELR:
                    std::println(f, "\tif (!ctx.cr{}.eq) return;", insn.operands[0]);
                    break;

                case PPC_INST_CCTPL:
                    // no op
                    break;

                case PPC_INST_CCTPM:
                    // no op
                    break;

                case PPC_INST_CLRLDI:
                    std::println(f, "\tctx.r{}.u64 = ctx.r{}.u64 & 0x{:X};", insn.operands[0], insn.operands[1], (1ull << (64 - insn.operands[2])) - 1);
                    break;

                case PPC_INST_CLRLWI:
                    std::println(f, "\tctx.r{}.u64 = ctx.r{}.u32 & 0x{:X};", insn.operands[0], insn.operands[1], (1ull << (32 - insn.operands[2])) - 1);
                    if (insn.opcode->opcode & 0x1)
                        std::println(f, "\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_CMPD:
                    std::println(f, "\tctx.cr{}.compare<int64_t>(ctx.r{}.s64, ctx.r{}.s64, ctx.xer);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_CMPDI:
                    std::println(f, "\tctx.cr{}.compare<int64_t>(ctx.r{}.s64, {}, ctx.xer);", insn.operands[0], insn.operands[1], int32_t(insn.operands[2]));
                    break;

                case PPC_INST_CMPLD:
                    std::println(f, "\tctx.cr{}.compare<uint64_t>(ctx.r{}.u64, ctx.r{}.u64, ctx.xer);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_CMPLDI:
                    std::println(f, "\tctx.cr{}.compare<uint64_t>(ctx.r{}.u64, {}, ctx.xer);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_CMPLW:
                    std::println(f, "\tctx.cr{}.compare<uint32_t>(ctx.r{}.u32, ctx.r{}.u32, ctx.xer);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_CMPLWI:
                    std::println(f, "\tctx.cr{}.compare<uint32_t>(ctx.r{}.u32, {}, ctx.xer);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_CMPW:
                    std::println(f, "\tctx.cr{}.compare<int32_t>(ctx.r{}.s32, ctx.r{}.s32, ctx.xer);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_CMPWI:
                    std::println(f, "\tctx.cr{}.compare<int32_t>(ctx.r{}.s32, {}, ctx.xer);", insn.operands[0], insn.operands[1], int32_t(insn.operands[2]));
                    break;

                case PPC_INST_CNTLZD:
                case PPC_INST_CNTLZW:
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
                case PPC_INST_DCBZ:
                case PPC_INST_DCBZL:
                case PPC_INST_DIVD:
                case PPC_INST_DIVDU:
                case PPC_INST_DIVW:
                case PPC_INST_DIVWU:
                    break;

                case PPC_INST_EIEIO:
                    // no op
                    break;

                case PPC_INST_EXTSB:
                case PPC_INST_EXTSH:
                case PPC_INST_EXTSW:
                case PPC_INST_FABS:
                case PPC_INST_FADD:
                case PPC_INST_FADDS:
                case PPC_INST_FCFID:
                case PPC_INST_FCMPU:
                case PPC_INST_FCTID:
                case PPC_INST_FCTIDZ:
                case PPC_INST_FCTIWZ:
                case PPC_INST_FDIV:
                case PPC_INST_FDIVS:
                case PPC_INST_FMADD:
                case PPC_INST_FMADDS:
                case PPC_INST_FMR:
                case PPC_INST_FMSUB:
                case PPC_INST_FMSUBS:
                case PPC_INST_FMUL:
                case PPC_INST_FMULS:
                case PPC_INST_FNABS:
                case PPC_INST_FNEG:
                case PPC_INST_FNMADDS:
                case PPC_INST_FNMSUB:
                case PPC_INST_FNMSUBS:
                case PPC_INST_FRES:
                case PPC_INST_FRSP:
                case PPC_INST_FSEL:
                case PPC_INST_FSQRT:
                case PPC_INST_FSQRTS:
                case PPC_INST_FSUB:
                case PPC_INST_FSUBS:
                    break;

                case PPC_INST_LBZ:
                    std::println(f, "\tctx.r{}.u64 = PPC_LOAD_U8({} + ctx.r{}.u32);", insn.operands[0], int32_t(insn.operands[1]), insn.operands[2]);
                    break;

                case PPC_INST_LBZU:
                    std::println(f, "\tea = {} + ctx.r{}.u32;", int32_t(insn.operands[1]), insn.operands[2]);
                    std::println(f, "\tctx.r{}.u64 = PPC_LOAD_U8(ea);", insn.operands[0]);
                    std::println(f, "\tctx.r{}.u64 = ea;", insn.operands[2]);
                    break;

                case PPC_INST_LBZX:
                    std::println(f, "\tctx.r{}.u64 = PPC_LOAD_U8(ctx.r{}.u32 + ctx.r{}.u32);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_LD:
                    std::println(f, "\tctx.r{}.u64 = PPC_LOAD_U64({} + ctx.r{}.u32);", insn.operands[0], int32_t(insn.operands[1]), insn.operands[2]);
                    break;

                case PPC_INST_LDARX:
                case PPC_INST_LDU:
                case PPC_INST_LDX:
                case PPC_INST_LFD:
                case PPC_INST_LFDX:
                case PPC_INST_LFS:
                case PPC_INST_LFSX:
                case PPC_INST_LHA:
                case PPC_INST_LHAX:
                case PPC_INST_LHZ:
                case PPC_INST_LHZX:
                    break;

                case PPC_INST_LI:
                    // TODO: validate the sign extend
                    std::println(f, "\tctx.r{}.s64 = {};", insn.operands[0], int32_t(insn.operands[1]));
                    break;

                case PPC_INST_LIS:
                    // TODO: validate the sign extend
                    std::println(f, "\tctx.r{}.s64 = {};", insn.operands[0], int32_t(insn.operands[1] << 16));
                    break;

                case PPC_INST_LVEWX:
                case PPC_INST_LVEWX128:
                case PPC_INST_LVLX:
                case PPC_INST_LVLX128:
                case PPC_INST_LVRX:
                case PPC_INST_LVRX128:
                case PPC_INST_LVSL:
                case PPC_INST_LVSR:
                case PPC_INST_LVX:
                case PPC_INST_LVX128:
                case PPC_INST_LWA:
                case PPC_INST_LWARX:
                case PPC_INST_LWAX:
                case PPC_INST_LWBRX:
                    break;

                case PPC_INST_LWSYNC:
                    // no op
                    break;

                case PPC_INST_LWZ:
                    std::println(f, "\tctx.r{}.u64 = PPC_LOAD_U32({} + ctx.r{}.u32);", insn.operands[0], int32_t(insn.operands[1]), insn.operands[2]);
                    break;

                case PPC_INST_LWZU:
                case PPC_INST_LWZX:
                case PPC_INST_MFCR:
                case PPC_INST_MFFS:
                    break;

                case PPC_INST_MFLR:
                    std::println(f, "\tctx.r{}.u64 = ctx.lr;", insn.operands[0]);
                    break;

                case PPC_INST_MFMSR:
                case PPC_INST_MFOCRF:
                case PPC_INST_MFTB:
                    break;

                case PPC_INST_MR:
                    std::println(f, "\tctx.r{}.u64 = ctx.r{}.u64;", insn.operands[0], insn.operands[1]);
                    if (insn.opcode->opcode & 0x1)
                        std::println(f, "\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_MTCR:
                    break;

                case PPC_INST_MTCTR:
                    std::println(f, "\tctx.ctr = ctx.r{}.u64;", insn.operands[0]);
                    break;

                case PPC_INST_MTFSF:
                    break;

                case PPC_INST_MTLR:
                    std::println(f, "\tctx.lr = ctx.r{}.u64;", insn.operands[0]);
                    break;

                case PPC_INST_MTMSRD:
                case PPC_INST_MTXER:
                case PPC_INST_MULCHWU:
                case PPC_INST_MULHHW:
                case PPC_INST_MULHW:
                case PPC_INST_MULHWU:
                case PPC_INST_MULLD:
                    break;

                case PPC_INST_MULLI:
                    std::println(f, "\tctx.r{}.s64 = ctx.r{}.s64 * {};", insn.operands[0], insn.operands[1], static_cast<int32_t>(insn.operands[2]));
                    break;

                case PPC_INST_MULLW:
                    std::println(f, "\tctx.r{}.s64 = ctx.r{}.s32 * ctx.r{}.s32;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        std::println(f, "\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_NAND:
                    std::println(f, "\tctx.r{}.u64 = ~(ctx.r{}.u64 & ctx.r{}.u64);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_NEG:
                    std::println(f, "\tctx.r{}.s64 = -ctx.r{}.s64;", insn.operands[0], insn.operands[1]);
                    if (insn.opcode->opcode & 0x1)
                        std::println(f, "\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_NOP:
                    // no op
                    break;

                case PPC_INST_NOR:
                    std::println(f, "\tctx.r{}.u64 = ~(ctx.r{}.u64 | ctx.r{}.u64);", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_NOT:
                    std::println(f, "\tctx.r{}.u64 = ~ctx.r{}.u64;", insn.operands[0], insn.operands[1]);
                    if (insn.opcode->opcode & 0x1)
                        std::println(f, "\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_OR:
                    std::println(f, "\tctx.r{}.u64 = ctx.r{}.u64 | ctx.r{}.u64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        std::println(f, "\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_ORC:
                    std::println(f, "\tctx.r{}.u64 = ctx.r{}.u64 | ~ctx.r{}.u64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_ORI:
                    std::println(f, "\tctx.r{}.u64 = ctx.r{}.u64 | {};", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_ORIS:
                    std::println(f, "\tctx.r{}.u64 = ctx.r{}.u64 | {}", insn.operands[0], insn.operands[1], insn.operands[2] << 16);
                    break;

                case PPC_INST_RLDICL:
                case PPC_INST_RLDICR:
                case PPC_INST_RLDIMI:
                case PPC_INST_RLWIMI:
                case PPC_INST_RLWINM:
                case PPC_INST_ROTLDI:
                case PPC_INST_ROTLW:
                case PPC_INST_ROTLWI:
                case PPC_INST_SLD:
                case PPC_INST_SLW:
                case PPC_INST_SRAD:
                case PPC_INST_SRADI:
                case PPC_INST_SRAW:
                case PPC_INST_SRAWI:
                case PPC_INST_SRD:
                case PPC_INST_SRW:
                case PPC_INST_STB:
                case PPC_INST_STBU:
                case PPC_INST_STBX:
                case PPC_INST_STD:
                case PPC_INST_STDCX:
                case PPC_INST_STDU:
                case PPC_INST_STDX:
                case PPC_INST_STFD:
                case PPC_INST_STFDX:
                case PPC_INST_STFIWX:
                case PPC_INST_STFS:
                case PPC_INST_STFSX:
                case PPC_INST_STH:
                case PPC_INST_STHBRX:
                case PPC_INST_STHX:
                case PPC_INST_STVEHX:
                case PPC_INST_STVEWX:
                case PPC_INST_STVEWX128:
                case PPC_INST_STVLX:
                case PPC_INST_STVLX128:
                case PPC_INST_STVRX:
                case PPC_INST_STVRX128:
                case PPC_INST_STVX:
                case PPC_INST_STVX128:
                    break;

                case PPC_INST_STW:
                    std::println(f, "\tPPC_STORE_U32({} + ctx.r{}.u32, ctx.r{}.u32);", int32_t(insn.operands[1]), insn.operands[2], insn.operands[0]);
                    break;

                case PPC_INST_STWBRX:
                case PPC_INST_STWCX:
                    break;

                case PPC_INST_STWU:
                    std::println(f, "\tea = {} + ctx.r{}.u32;", int32_t(insn.operands[1]), insn.operands[2]);
                    std::println(f, "\tPPC_STORE_U32(ea, ctx.r{}.u32);", insn.operands[0]);
                    std::println(f, "\tctx.r{}.u64 = ea;", insn.operands[0]);
                    break;

                case PPC_INST_STWUX:
                case PPC_INST_STWX:
                    break;

                case PPC_INST_SUBF:
                    std::println(f, "\tctx.r{}.s64 = ctx.r{}.s64 - ctx.r{}.s64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        std::println(f, "\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_SUBFC:
                case PPC_INST_SUBFE:
                case PPC_INST_SUBFIC:
                case PPC_INST_SYNC:
                case PPC_INST_TDLGEI:
                case PPC_INST_TDLLEI:
                case PPC_INST_TWI:
                case PPC_INST_TWLGEI:
                case PPC_INST_TWLLEI:
                case PPC_INST_VADDFP:
                case PPC_INST_VADDFP128:
                case PPC_INST_VADDSHS:
                case PPC_INST_VADDUBM:
                case PPC_INST_VADDUBS:
                case PPC_INST_VADDUHM:
                case PPC_INST_VADDUWM:
                case PPC_INST_VADDUWS:
                case PPC_INST_VAND:
                case PPC_INST_VAND128:
                case PPC_INST_VANDC128:
                case PPC_INST_VAVGSB:
                case PPC_INST_VAVGSH:
                case PPC_INST_VAVGUB:
                case PPC_INST_VCFPSXWS128:
                case PPC_INST_VCFSX:
                case PPC_INST_VCFUX:
                case PPC_INST_VCMPBFP128:
                case PPC_INST_VCMPEQFP:
                case PPC_INST_VCMPEQFP128:
                case PPC_INST_VCMPEQUB:
                case PPC_INST_VCMPEQUW:
                case PPC_INST_VCMPEQUW128:
                case PPC_INST_VCMPGEFP:
                case PPC_INST_VCMPGEFP128:
                case PPC_INST_VCMPGTFP:
                case PPC_INST_VCMPGTFP128:
                case PPC_INST_VCMPGTUB:
                case PPC_INST_VCMPGTUH:
                case PPC_INST_VCSXWFP128:
                case PPC_INST_VCTSXS:
                case PPC_INST_VCUXWFP128:
                case PPC_INST_VEXPTEFP128:
                case PPC_INST_VLOGEFP128:
                case PPC_INST_VMADDCFP128:
                case PPC_INST_VMADDFP:
                case PPC_INST_VMADDFP128:
                case PPC_INST_VMAXFP:
                case PPC_INST_VMAXFP128:
                case PPC_INST_VMAXSW:
                case PPC_INST_VMINFP:
                case PPC_INST_VMINFP128:
                case PPC_INST_VMRGHB:
                case PPC_INST_VMRGHH:
                case PPC_INST_VMRGHW:
                case PPC_INST_VMRGHW128:
                case PPC_INST_VMRGLB:
                case PPC_INST_VMRGLH:
                case PPC_INST_VMRGLW:
                case PPC_INST_VMRGLW128:
                case PPC_INST_VMSUM3FP128:
                case PPC_INST_VMSUM4FP128:
                case PPC_INST_VMULFP128:
                case PPC_INST_VNMSUBFP:
                case PPC_INST_VNMSUBFP128:
                case PPC_INST_VOR:
                case PPC_INST_VOR128:
                case PPC_INST_VPERM:
                case PPC_INST_VPERM128:
                case PPC_INST_VPERMWI128:
                case PPC_INST_VPKD3D128:
                case PPC_INST_VPKSHUS:
                case PPC_INST_VREFP:
                case PPC_INST_VREFP128:
                case PPC_INST_VRFIM128:
                case PPC_INST_VRFIN:
                case PPC_INST_VRFIN128:
                case PPC_INST_VRFIZ128:
                case PPC_INST_VRLIMI128:
                case PPC_INST_VRSQRTEFP:
                case PPC_INST_VRSQRTEFP128:
                case PPC_INST_VSEL:
                case PPC_INST_VSLB:
                case PPC_INST_VSLDOI:
                case PPC_INST_VSLDOI128:
                case PPC_INST_VSLW128:
                case PPC_INST_VSPLTH:
                case PPC_INST_VSPLTISB:
                case PPC_INST_VSPLTISW:
                case PPC_INST_VSPLTISW128:
                case PPC_INST_VSPLTW:
                case PPC_INST_VSPLTW128:
                case PPC_INST_VSR:
                case PPC_INST_VSRAW128:
                case PPC_INST_VSRW:
                case PPC_INST_VSRW128:
                case PPC_INST_VSUBFP:
                case PPC_INST_VSUBFP128:
                case PPC_INST_VSUBSWS:
                case PPC_INST_VSUBUBS:
                case PPC_INST_VSUBUHM:
                case PPC_INST_VUPKD3D128:
                case PPC_INST_VUPKHSB128:
                case PPC_INST_VUPKHSH:
                case PPC_INST_VUPKLSB128:
                case PPC_INST_VUPKLSH:
                case PPC_INST_VXOR:
                case PPC_INST_VXOR128:
                    break;

                case PPC_INST_XOR:
                    std::println(f, "\tctx.r{}.u64 = ctx.r{}.u64 ^ ctx.r{}.u64;", insn.operands[0], insn.operands[1], insn.operands[2]);
                    if (insn.opcode->opcode & 0x1)
                        std::println(f, "\tctx.cr0.compare<int32_t>(ctx.r{}.s32, 0, ctx.xer);", insn.operands[0]);
                    break;

                case PPC_INST_XORI:
                    std::println(f, "\tctx.r{}.u64 = ctx.r{}.u64 ^ {};", insn.operands[0], insn.operands[1], insn.operands[2]);
                    break;

                case PPC_INST_XORIS:
                    std::println(f, "\tctx.r{}.u64 = ctx.r{}.u64 ^ {};", insn.operands[0], insn.operands[1], insn.operands[2] << 16);
                    break;
                }
            }
        }

        std::println(f, "}}\n");
    }

    fclose(f);

    return 0;
}
