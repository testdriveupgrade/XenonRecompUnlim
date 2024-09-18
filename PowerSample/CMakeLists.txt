project("PowerSample")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_COMPILER "clang-cl")
set(CMAKE_C_COMPILER "clang-cl")
add_compile_options("-march=x86-64-v3")

file(GLOB RecompiledFiles *.cpp)
add_library(PowerSample SHARED ${RecompiledFiles})

target_precompile_headers(PowerSample PUBLIC "ppc_recomp_shared.h")

target_link_libraries(PowerSample PUBLIC PowerUtils)
