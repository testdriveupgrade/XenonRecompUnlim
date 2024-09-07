#include "xex.h"
#include "image.h"
#include <cassert>

Image Xex2LoadImage(const uint8_t* data)
{
    auto* header = reinterpret_cast<const XEX_HEADER*>(data);
    auto* security = reinterpret_cast<const XEX2_SECURITY_INFO*>(data + header->AddressOfSecurityInfo);

    const auto* compressionInfo = Xex2FindOptionalHeader<XEX_FILE_FORMAT_INFO>(header, XEX_HEADER_FILE_FORMAT_INFO);

    Image image{};
    std::unique_ptr<uint8_t[]> result{};
    size_t imageSize = security->SizeOfImage;

    // Decompress image
    if (compressionInfo != nullptr)
    {
        assert(compressionInfo->CompressionType >= XEX_COMPRESSION_BASIC);
        assert(compressionInfo->EncryptionType == XEX_ENCRYPTION_NONE);

        if (compressionInfo->CompressionType == XEX_COMPRESSION_NONE)
        {
            result = std::make_unique<uint8_t[]>(imageSize);
            memcpy(result.get(), data + header->SizeOfHeader, imageSize);
        }
        else if (compressionInfo->CompressionType == XEX_COMPRESSION_BASIC)
        {
            auto* blocks = reinterpret_cast<const XEX_BASIC_FILE_COMPRESSION_INFO*>(compressionInfo + 1);
            const size_t numBlocks = (compressionInfo->SizeOfHeader / sizeof(XEX_BASIC_FILE_COMPRESSION_INFO)) - 1;

            imageSize = 0;
            for (size_t i = 0; i < numBlocks; i++)
            {
                imageSize += blocks[i].SizeOfData + blocks[i].SizeOfPadding;
            }

            result = std::make_unique<uint8_t[]>(imageSize);
            auto* srcData = data + header->SizeOfHeader;
            auto* destData = result.get();

            for (size_t i = 0; i < numBlocks; i++)
            {
                memcpy(destData, srcData, blocks[i].SizeOfData);

                srcData += blocks[i].SizeOfData;
                destData += blocks[i].SizeOfData;

                memset(destData, 0, blocks[i].SizeOfPadding);
                destData += blocks[i].SizeOfPadding;
            }
        }
    }

    image.data = std::move(result);
    image.size = imageSize;

    // Map image
    const auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data.get());
    const auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS32*>(image.data.get() + dosHeader->e_lfanew);

    image.base = ntHeaders->OptionalHeader.ImageBase;
    image.entry_point = image.base + ntHeaders->OptionalHeader.AddressOfEntryPoint;

    const auto numSections = ntHeaders->FileHeader.NumberOfSections;
    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(ntHeaders + 1);

    for (size_t i = 0; i < numSections; i++)
    {
        const auto& section = sections[i];
        uint8_t flags{};

        if (section.Characteristics & IMAGE_SCN_CNT_CODE)
        {
            flags |= SectionFlags_Code;
        }

        image.Map(reinterpret_cast<const char*>(section.Name), section.VirtualAddress, 
            section.Misc.VirtualSize, flags, image.data.get() + section.VirtualAddress);
    }

    return image;
}