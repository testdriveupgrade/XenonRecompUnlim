project("XenonUtils")

add_library(XenonUtils
    "disasm.cpp" 
    "xex.cpp" 
    "image.cpp" 
    "xdbf_wrapper.cpp")

target_include_directories(XenonUtils PUBLIC .)
target_link_libraries(XenonUtils PUBLIC disasm)
