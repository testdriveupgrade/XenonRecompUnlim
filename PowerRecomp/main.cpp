#include "pch.h"
#include "test_recompiler.h"

int main(int argc, char* argv[])
{
    const char* path = 
    #ifdef CONFIG_FILE_PATH
        CONFIG_FILE_PATH
    #else
        argv[1]
    #endif
        ;

    if (std::filesystem::is_regular_file(path))
    {
        Recompiler recompiler;
        recompiler.LoadConfig(path);
        recompiler.Analyse();

        auto entry = recompiler.image.symbols.find(recompiler.image.entry_point);
        if (entry != recompiler.image.symbols.end())
        {
            entry->name = "_xstart";
        }

        const char* headerFilePath =
#ifdef HEADER_FILE_PATH
            HEADER_FILE_PATH
#else
            argv[2]
#endif
            ;

        recompiler.Recompile(headerFilePath);
    }
    else
    {
        TestRecompiler::RecompileTests(path, argv[2]);
    }

    return 0;
}
