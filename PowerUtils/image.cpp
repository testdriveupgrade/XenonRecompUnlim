#include "image.h"
#include "elf.h"
#include "xex.h"
#include <cassert>

void Image::Map(const std::string_view& name, size_t base, uint32_t size, uint8_t flags, uint8_t* data)
{
    sections.emplace(std::string(name), this->base + base, 
        size, static_cast<SectionFlags>(flags), data);
}

const void* Image::Find(size_t address) const
{
    const auto section = std::prev(sections.upper_bound(address));
    return section->data + (address - section->base);
}

const Section* Image::Find(const std::string_view& name) const
{
    for (const auto& section : sections)
    {
        if (section.name == name)
        {
            return &section;
        }
    }

    return nullptr;
}

std::expected<Image, int> Image::ParseImage(const uint8_t* data, size_t size)
{
    if (data[0] == ELFMAG0 && data[1] == ELFMAG1 && data[2] == ELFMAG2 && data[3] == ELFMAG3)
    {
        return ElfLoadImage(data, size);
    }
    else if (data[0] == 'X' && data[1] == 'E' && data[2] == 'X' && data[3] == '2')
    {
        return Xex2LoadImage(data);
    }

    return std::unexpected(1);
}

Image ElfLoadImage(const uint8_t* data, size_t size)
{
    const auto* header = (elf32_hdr*)data;
    assert(header->e_ident[EI_DATA] == 2);

    Image image{};
    image.size = size;
    image.data = std::make_unique<uint8_t[]>(size);
    image.entry_point = std::byteswap(header->e_entry);
    memcpy(image.data.get(), data, size);

    auto stringTableIndex = std::byteswap(header->e_shstrndx);

    const auto numSections = std::byteswap(header->e_shnum);
    const auto numpSections = std::byteswap(header->e_phnum);

    const auto* sections = (elf32_shdr*)(data + std::byteswap(header->e_shoff));
    const auto* psections = (elf32_phdr*)(data + std::byteswap(header->e_phoff));

    for (size_t i = 0; i < numpSections; i++)
    {
        if (psections[i].p_type == std::byteswap((Elf32_Word)PT_LOAD))
        {
            image.base = std::byteswap(psections[i].p_vaddr);
            break;
        }
    }

    auto* stringTable = reinterpret_cast<const char*>(data + std::byteswap(sections[stringTableIndex].sh_offset));

    for (size_t i = 0; i < numSections; i++)
    {
        const auto& section = sections[i];
        if (section.sh_type == 0)
        {
            continue;
        }

        uint8_t flags{};

        if (section.sh_flags & std::byteswap(SHF_EXECINSTR))
        {
            flags |= SectionFlags_Code;
        }

        auto* name = section.sh_name != 0 ? stringTable + std::byteswap(section.sh_name) : nullptr;
        const auto rva = std::byteswap(section.sh_addr) - image.base;
        const auto size = std::byteswap(section.sh_size);

        image.Map(name, rva, size, flags, image.data.get() + std::byteswap(section.sh_offset));
    }

    return image;
}
