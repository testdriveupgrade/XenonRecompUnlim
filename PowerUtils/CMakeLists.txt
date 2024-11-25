project("PowerUtils")
add_library(PowerUtils "disasm.h" "disasm.cpp" "file.h" "xex.cpp" "image.h" "image.cpp" "elf.h" "ppc_context.h" "symbol.h" "symbol_table.h" "section.h" "xdbf_wrapper.cpp")

target_include_directories(PowerUtils PUBLIC .)
target_link_libraries(PowerUtils PUBLIC disasm)
