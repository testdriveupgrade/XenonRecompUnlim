#include <file.h>
#include <disasm.h>
#include <image.h>

int main()
{
    // TODO: ELFs, symbols, sections, a lot
    const auto file = LoadFile("add.elf");
    const auto image = Image::ParseImage(file.data(), file.size()).value();

    for (const auto& section : image.sections)
    {
        std::printf("Section %.8s\n", section.name.c_str());
        std::printf("\t%X-%X\n", section.base, section.base + section.size);

        auto* data = (uint32_t*)section.data;
        auto base = section.base;
        const auto end = section.base + section.size;

        ppc::SetDetail(true);

        if (section.flags & SectionFlags_Code)
        {
            while(base < end)
            {
                auto* instruction = ppc::DisassembleSingle(reinterpret_cast<uint8_t*>(data), base);

                base += 4;
                ++data;

                if (instruction == nullptr)
                {
                    printf("\t%X\t.long %Xh\n", static_cast<uint32_t>(base - 4), *(data - 1));
                }
                else
                {
                    std::printf("\t%X\t%s %s\n", static_cast<uint32_t>(base - 4), instruction->mnemonic, instruction->op_str);
                    cs_free(instruction, 1);
                }
            }
        }
    }

    return 0;
}
