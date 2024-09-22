project("PowerSample")

add_compile_options(
    "-march=x86-64-v3"
    "-Wno-unused-label"
    "-Wno-unused-variable")

file(GLOB RecompiledFiles *.cpp)
add_library(PowerSample ${RecompiledFiles})

target_precompile_headers(PowerSample PUBLIC "ppc_recomp_shared.h")

target_link_libraries(PowerSample PUBLIC PowerUtils)
