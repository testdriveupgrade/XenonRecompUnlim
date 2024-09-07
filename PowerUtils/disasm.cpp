#include "disasm.h"

DisassemblerEngine ppc::gPPCBigEndianDisassembler{ CS_ARCH_PPC, CS_MODE_BIG_ENDIAN };

DisassemblerEngine::DisassemblerEngine(cs_arch arch, cs_mode mode)
{
    cs_open(arch, mode, &handle);
}

size_t DisassemblerEngine::Disassemble(const uint8_t* code, size_t size, uint64_t base, size_t count, cs_insn** instructions) const
{
    return cs_disasm(handle, code, size, base, count, instructions);
}

void DisassemblerEngine::SetOption(cs_opt_type option, size_t value)
{
    cs_option(handle, option, value);
}

DisassemblerEngine::~DisassemblerEngine()
{
    cs_close(&handle);
}
