#include "pch.h"
#include "swa_recompiler.h"

// argv 1: xex file path
// argv 2: switches toml file path
// argv 3: output directory path

int main(int argc, char* argv[])
{
    SWARecompiler recompiler;

    std::println("Loading executable...");
    recompiler.LoadExecutable(argv[1]);

    std::println("Loading switch tables...");
    recompiler.LoadSwitchTables(argv[2]);

    std::println("Analysing functions...");
    recompiler.Analyse();
    
    recompiler.Recompile(argv[3]);

    return 0;
}
