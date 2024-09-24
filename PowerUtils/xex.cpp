#include "xex.h"
#include "image.h"
#include <cassert>
#include <vector>
#include <unordered_map>

#define STRINGIFY(X) #X
#define XE_EXPORT(MODULE, ORDINAL, NAME, TYPE) { (ORDINAL), STRINGIFY(NAME) }

std::unordered_map<size_t, const char*> XamExports = 
{
    #include "xbox/xam_table.inc"
};

std::unordered_map<size_t, const char*> XboxKernelExports =
{
    #include "xbox/xboxkrnl_table.inc"
};

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

    auto* imports = Xex2FindOptionalHeader<XEX_IMPORT_HEADER>(header, XEX_HEADER_IMPORT_LIBRARIES);
    if (imports != nullptr)
    {
        std::vector<std::string_view> stringTable;
        auto* pStrTable = reinterpret_cast<const char*>(imports + 1);

        for (size_t i = 0; i < imports->NumImports; i++)
        {
            stringTable.emplace_back(pStrTable);
            pStrTable += strlen(pStrTable) + 1;
        }

        auto* library = (XEX_IMPORT_LIBRARY*)(((char*)imports) + sizeof(XEX_IMPORT_HEADER) + imports->SizeOfStringTable);
        for (size_t i = 0; i < stringTable.size(); i++)
        {
            auto* descriptors = (XEX_IMPORT_DESCRIPTOR*)(library + 1);
            static std::unordered_map<size_t, const char*> DummyExports;
            const std::unordered_map<size_t, const char*>* names = &DummyExports;

            if (stringTable[i] == "xam.xex")
            {
                names = &XamExports;
            }
            else if (stringTable[i] == "xboxkrnl.exe")
            {
                names = &XboxKernelExports;
            }

            for (size_t im = 0; im < library->NumberOfImports; im++)
            {
                auto originalThunk = (XEX_THUNK_DATA*)image.Find(descriptors[im].FirstThunk);
                auto thunkType = originalThunk->Function >> 24;

                if (thunkType != 0)
                {
                    uint32_t thunk[4] = { 0x00000060, 0x00000060, 0x00000060, 0x2000804E };
                    auto name = names->find(originalThunk->OriginalData.Ordinal);
                    if (name != names->end())
                    {
                        image.symbols.emplace(name->second, descriptors[im].FirstThunk, sizeof(thunk), Symbol_Function);
                    }

                    memcpy(originalThunk, thunk, sizeof(thunk));
                }
            }
            library = (XEX_IMPORT_LIBRARY*)((char*)(library + 1) + library->NumberOfImports * sizeof(XEX_IMPORT_DESCRIPTOR));
        }
    }

    return image;
}
