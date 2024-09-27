project("PowerSample")

add_compile_options(
    "/fp:strict"
    "/GS-"
    "-march=haswell"
    "-fno-strict-aliasing")

file(GLOB RecompiledFiles *.cpp)
add_library(PowerSample ${RecompiledFiles})

target_precompile_headers(PowerSample PUBLIC "ppc_recomp_shared.h")

target_link_libraries(PowerSample PUBLIC PowerUtils)
