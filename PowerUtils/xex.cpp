#include "xex.h"
#include <cassert>

std::unique_ptr<uint8_t[]> Xex2LoadImage(const uint8_t* data)
{
	auto* header = reinterpret_cast<const XEX_HEADER*>(data);
	auto* security = reinterpret_cast<const XEX2_SECURITY_INFO*>(data + header->AddressOfSecurityInfo);

	const auto* compressionInfo = Xex2FindOptionalHeader<XEX_FILE_FORMAT_INFO>(header, XEX_HEADER_FILE_FORMAT_INFO);

	std::unique_ptr<uint8_t[]> result{};
	size_t imageSize = security->SizeOfImage;

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

	return result;
}