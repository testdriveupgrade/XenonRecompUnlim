project("disasm")

add_library(disasm "ppc-dis.c" "disasm.c")
target_include_directories(disasm PUBLIC .)
