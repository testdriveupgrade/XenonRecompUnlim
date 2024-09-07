#pragma once
#include <vector>

inline static std::vector<uint8_t> LoadFile(const char* path)
{
	std::vector<uint8_t> data{};
	auto* stream = fopen(path, "rb");
	if (stream == nullptr)
	{
		return data;
	}

	fseek(stream, 0, SEEK_END);

	const auto size = ftell(stream);

	fseek(stream, 0, SEEK_SET);

	data.resize(size);

	fread(data.data(), 1, data.size(), stream);
	fclose(stream);

	return data;
}