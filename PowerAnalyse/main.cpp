#include <file.h>
#include <disasm.h>
#include <image.h>
#include <format>
#include <print>
#include <ppc.h>

int main()
{
    const auto file = LoadFile("add.elf");
    auto image = Image::ParseImage(file.data(), file.size()).value();
    FILE* f = fopen("add.elf.cpp", "w");

    for (const auto& section : image.sections)
    {
        image.symbols.emplace(section.name, section.base, section.size, Symbol_Section);
    }

    // image.symbols.emplace("_start", image.entry_point, 0x30, Symbol_Function);

    for (const auto& section : image.sections)
    {
        std::printf("Section %.8s\n", section.name.c_str());
        std::printf("\t%X-%X\n", section.base, section.base + section.size);

        auto* data = (uint32_t*)section.data;
        auto base = section.base;
        const auto end = section.base + section.size;

        if (section.flags & SectionFlags_Code)
        {
            ppc_insn insn;
            while(base < end)
            {
                ppc::Disassemble(data, 4, base, insn);

                base += 4;
                ++data;
                if (insn.opcode == nullptr)
                {
                    std::println(f, "// {:x} {}", base - 4, insn.op_str);
                }
                else
                {
                    std::println(f, "// {:x} {} {}", base - 4, insn.opcode->name, insn.op_str);
                    switch (insn.opcode->id)
                    {
                    case PPC_INST_ADD:
                        std::println(f, "r{} = r{} + r{};", insn.operands[0], insn.operands[1], insn.operands[2]);
                        break;
                    case PPC_INST_ADDI:
                        std::println(f, "r{} = r{} + {};", insn.operands[0], insn.operands[1], insn.operands[2]);
                        break;
                    case PPC_INST_STWU:
                        std::println(f, "ea = r{} + {};", insn.operands[2], static_cast<int32_t>(insn.operands[1]));
                        std::println(f, "*ea = byteswap(r{});", insn.operands[0]);
                        std::println(f, "r{} = ea;", insn.operands[2]);
                        break;
                    case PPC_INST_STW:
                        std::println(f, "*(r{} + {}) = byteswap(r{});", insn.operands[2], static_cast<int32_t>(insn.operands[1]), insn.operands[0]);
                        break;
                    case PPC_INST_MR:
                        std::println(f, "r{} = r{};", insn.operands[0], insn.operands[1]);
                        break;
                    case PPC_INST_LWZ:
                        std::println(f, "r{} = *(r{} + {});", insn.operands[0], insn.operands[2], insn.operands[1]);
                        break;
                    case PPC_INST_LI:
                        std::println(f, "r{} = {};", insn.operands[0], insn.operands[1]);
                        break;
                    case PPC_INST_MFLR:
                        std::println(f, "r{} = lr;", insn.operands[0]);
                        break;
                    case PPC_INST_MTLR:
                        std::println(f, "lr = r{};", insn.operands[0]);
                        break;
                    case PPC_INST_BLR:
                        std::println(f, "return;");
                        break;
                    case PPC_INST_BL:
                        std::println(f, "lr = 0x{:x};", insn.operands[0]);
                        std::println(f, "sub_{:x}();", insn.operands[0]);
                        break;
                    }
                }
            }
        }
    }

    fclose(f);

    return 0;
}
