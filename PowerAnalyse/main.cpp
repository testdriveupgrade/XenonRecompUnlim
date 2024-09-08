#include <file.h>
#include <disasm.h>
#include <image.h>

int main()
{
    const auto file = LoadFile("add.elf");
    auto image = Image::ParseImage(file.data(), file.size()).value();
    
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
                    printf("\t%X\t%s\n", static_cast<uint32_t>(base - 4), insn.op_str);
                }
                else
                {
                    std::printf("\t%X\t%s %s\n", static_cast<uint32_t>(base - 4), insn.opcode->name, insn.op_str);
                }
            }
        }
    }

    return 0;
}
