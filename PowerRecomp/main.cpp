#include "pch.h"
#include "swa_recompiler.h"
#include "test_recompiler.h"

// argv 1: xex file path
// argv 2: switches toml file path
// argv 3: output directory path

int main(int argc, char* argv[])
{
    if (strstr(argv[1], ".xex") != nullptr)
    {
        SWARecompiler recompiler;
        //recompiler.config.skipLr = true;
        recompiler.config.ctrAsLocalVariable = true;
        recompiler.config.xerAsLocalVariable = true;
        recompiler.config.reservedRegisterAsLocalVariable = true;
        recompiler.config.skipMsr = true;
        recompiler.config.crRegistersAsLocalVariables = true;
        recompiler.config.nonArgumentRegistersAsLocalVariables = true;
        recompiler.config.nonVolatileRegistersAsLocalVariables = true;

        std::println("Loading executable...");
        recompiler.LoadExecutable(argv[1]);

        std::println("Loading switch tables...");
        recompiler.LoadSwitchTables(argv[2]);

        std::println("Analysing functions...");
        recompiler.Analyse();

        auto entry = recompiler.image.symbols.find(recompiler.image.entry_point);
        if (entry != recompiler.image.symbols.end())
        {
            entry->name = "_xstart";
        }

        recompiler.Recompile(argv[3]);
    }
    else
    {
        TestRecompiler::RecompileTests(argv[1], argv[2]);
    }

    return 0;
}
