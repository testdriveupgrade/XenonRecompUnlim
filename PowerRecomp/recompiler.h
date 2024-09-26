#pragma once
#include "pch.h"

struct SwitchTable
{
    size_t r;
    std::vector<size_t> labels;
};

struct RecompilerLocalVariables
{
    bool ctr{};
    bool xer{};
    bool reserved{};
    bool cr[8]{};
    bool r[32]{};
    bool f[32]{};
    bool v[128]{};
    bool env{};
    bool temp{};
    bool vTemp{};
    bool ea{};
};

struct RecompilerConfig
{
    bool skipLr = false;
    bool ctrAsLocalVariable = false;
    bool xerAsLocalVariable = false;
    bool reservedRegisterAsLocalVariable = false;
    bool skipMsr = false;
    bool crRegistersAsLocalVariables = false;
    bool nonArgumentRegistersAsLocalVariables = false;
    bool nonVolatileRegistersAsLocalVariables = false;
};

enum class CSRState
{
    Unknown,
    FPU,
    VMX
};

struct Recompiler
{
    Image image;
    std::vector<Function> functions;
    std::unordered_map<size_t, SwitchTable> switchTables;
    std::string out;
    size_t cppFileIndex = 0;
    uint32_t setJmpAddress = 0;
    uint32_t longJmpAddress = 0;
    RecompilerConfig config;

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

    // TODO: make a RecompileArgs struct instead this is getting messy
    bool Recompile(
        const Function& fn,
        uint32_t base,
        const ppc_insn& insn, 
        std::unordered_map<size_t, SwitchTable>::iterator& switchTable, 
        RecompilerLocalVariables& localVariables,
        CSRState& csrState);

    bool Recompile(const Function& fn);

    void Recompile(const char* directoryPath);

    void SaveCurrentOutData(const char* directoryPath, const std::string_view& name = std::string_view());
};
