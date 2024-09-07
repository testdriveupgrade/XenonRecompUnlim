#pragma once
#include <capstone/capstone.h>

struct DisassemblerEngine
{
    csh handle{};

    DisassemblerEngine(const DisassemblerEngine&) = default;
    DisassemblerEngine& operator=(const DisassemblerEngine&) = delete;

    DisassemblerEngine(cs_arch arch, cs_mode mode);
    ~DisassemblerEngine();
    size_t Disassemble(const uint8_t* code, size_t size, uint64_t base, size_t count, cs_insn** instructions) const;
    void SetOption(cs_opt_type option, size_t value);

    void SetDetail(bool value)
    {
        SetOption(CS_OPT_DETAIL, value);
    }
};

namespace ppc
{
    extern DisassemblerEngine gPPCBigEndianDisassembler;

    static size_t Disassemble(const uint8_t* code, size_t size, uint64_t base, size_t count, cs_insn** instructions)
    {
        return gPPCBigEndianDisassembler.Disassemble(code, size, base, count, instructions);
    }

    static cs_insn* DisassembleSingle(const uint8_t* code, uint64_t base)
    {
        cs_insn* instruction{};
        gPPCBigEndianDisassembler.Disassemble(code, 4, base, 1, &instruction);

        return instruction;
    }

    static void SetDetail(bool value)
    {
        gPPCBigEndianDisassembler.SetDetail(value);
    }
}