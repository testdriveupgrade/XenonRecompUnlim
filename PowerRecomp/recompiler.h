#pragma once
#include "pch.h"

struct SwitchTable
{
    size_t r;
    std::vector<size_t> labels;
};

struct Recompiler
{
    Image image;
    std::vector<Function> functions;
    std::unordered_map<size_t, SwitchTable> switchTables;
    std::string out;
    size_t cppFileIndex = 0;
    std::vector<uint8_t> temp;

    void LoadSwitchTables(const char* filePath);
    void LoadExecutable(const char* filePath);

    template<class... Args>
    void print(std::format_string<Args...> fmt, Args&&... args)
    {
        std::vformat_to(std::back_inserter(out), fmt.get(), std::make_format_args(args...));
    }

    template<class... Args>
    void println(std::format_string<Args...> fmt, Args&&... args)
    {
        std::vformat_to(std::back_inserter(out), fmt.get(), std::make_format_args(args...));
        out += '\n';
    }

    bool Recompile(const Function& fn, uint32_t base, const ppc_insn& insn, std::unordered_map<size_t, SwitchTable>::iterator& switchTable);

    bool Recompile(const Function& fn);

    void Recompile(const char* directoryPath);

    void SaveCurrentOutData(const char* directoryPath, const std::string_view& name = std::string_view());
};
