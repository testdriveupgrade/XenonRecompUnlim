#include <windows.h>
#include <xex.h>
#include <file.h>
#include <disasm.h>

int main()
{
	// TODO: ELFs, symbols, sections, a lot
	const auto file = LoadFile("default.xex");
	const auto image = Xex2LoadImage(file.data());

	auto* headers = (IMAGE_NT_HEADERS32*)(image.get() + ((IMAGE_DOS_HEADER*)image.get())->e_lfanew);
	auto numSections = headers->FileHeader.NumberOfSections;
	auto* sections = (IMAGE_SECTION_HEADER*)(headers + 1);
	auto base = headers->OptionalHeader.ImageBase;

	for (size_t i = 0; i < numSections; i++)
	{
		const auto& section = sections[i];
		std::printf("Section %.8s\n", reinterpret_cast<const char*>(section.Name));
		std::printf("\t%X-%X\n", base + section.VirtualAddress, base + section.VirtualAddress + section.Misc.VirtualSize);

		auto* data = image.get() + section.VirtualAddress; // XEX is weird
		ppc::SetDetail(true);

		if (section.Characteristics & IMAGE_SCN_CNT_CODE)
		{
			cs_insn* instructions;
			size_t n = ppc::Disassemble(data, section.SizeOfRawData, base + section.VirtualAddress, 0, &instructions);

			for(size_t i = 0; i < n; i++)
			{
				printf("\t%s\n", instructions[i].mnemonic);
			}

			cs_free(instructions, n);
		}
	}

	return 0;
}