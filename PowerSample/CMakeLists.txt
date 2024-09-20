project("PowerSample")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_COMPILER "clang-cl")
set(CMAKE_C_COMPILER "clang-cl")
add_compile_options(
    "/clang:-march=x86-64-v3" 
    "/clang:-Wall" 
    "/clang:-Wno-unused-label" 
    "/clang:-Wno-unused-variable"
    "/clang:-Wno-c++23-extensions")

file(GLOB RecompiledFiles *.cpp)
add_library(PowerSample ${RecompiledFiles})

target_precompile_headers(PowerSample PUBLIC "ppc_recomp_shared.h")

target_link_libraries(PowerSample PUBLIC PowerUtils)
