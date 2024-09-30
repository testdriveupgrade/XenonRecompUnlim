#pragma once

#include "pch.h"
#include "recompiler_config.h"

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
    std::string out;
    size_t cppFileIndex = 0;
    RecompilerConfig config;

    void LoadConfig(const std::string_view& configFilePath);

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

    void Analyse();

    // TODO: make a RecompileArgs struct instead this is getting messy
    bool Recompile(
        const Function& fn,
        uint32_t base,
        const ppc_insn& insn, 
        std::unordered_map<uint32_t, RecompilerSwitchTable>::iterator& switchTable,
        RecompilerLocalVariables& localVariables,
        CSRState& csrState);

    bool Recompile(const Function& fn);

    void Recompile();

    void SaveCurrentOutData(const std::string_view& name = std::string_view());
};
