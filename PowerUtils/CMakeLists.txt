project("PowerUtils")
add_library(PowerUtils "disasm.h" "disasm.cpp" "file.h" "xex.cpp")

target_include_directories(PowerUtils PUBLIC .)
target_link_libraries(PowerUtils PUBLIC capstone)