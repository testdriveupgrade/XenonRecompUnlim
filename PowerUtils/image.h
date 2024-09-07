#pragma once
#include <memory>
#include <string>
#include <vector>
#include <expected>

struct Section;
enum SectionFlags : uint8_t
{
    SectionFlags_None = 0,
    SectionFlags_Data = 1,
    SectionFlags_Code = 2
};

struct Image
{
    std::unique_ptr<uint8_t[]> data{};
    size_t base{};
    uint32_t size{};

    size_t entry_point{};
    std::vector<Section> sections{};

    /**
     * \brief Map data to image by RVA
     * \param name Name of section
     * \param base Section RVA
     * \param size Section Size
     * \param flags Section Flags, enum SectionFlags
     * \param data Section data
     */
    void Map(const std::string_view& name, size_t base, uint32_t size, uint8_t flags, uint8_t* data);

    /**
     * \param address Virtual Address
     * \return Pointer to image owned data
     */
    const void* Find(size_t address) const;

    /**
     * \brief Parse given data to an image, reallocates with ownership
     * \param data Pointer to data
     * \param size Size of data
     * \return Parsed image
     */
    static std::expected<Image, int> ParseImage(const uint8_t* data, size_t size);
};

struct Section
{
    std::string name{};
    size_t base{};
    uint32_t size{};
    SectionFlags flags{};
    uint8_t* data{};

    bool operator<(size_t address) const
    {
        return address < base;
    }

    bool operator>(size_t address) const
    {
        return address >= (base + size);
    }

    bool operator==(size_t address) const
    {
        return address >= base && address < base + size;
    }
};

Image ElfLoadImage(const uint8_t* data, size_t size);
