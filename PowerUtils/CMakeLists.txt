project("PowerUtils")
add_library(PowerUtils "disasm.h" "disasm.cpp" "file.h" "xex.cpp" "image.h" "image.cpp" "elf.h")

target_include_directories(PowerUtils PUBLIC .)
target_link_libraries(PowerUtils PUBLIC capstone)