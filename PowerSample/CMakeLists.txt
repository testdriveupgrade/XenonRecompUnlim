project("PowerSample")

add_compile_options(
    "/D_HAS_EXCEPTIONS=0"
    "/fp:strict"
    "/GS-"
    "/EHa-"
    "-march=haswell"
    "-fno-strict-aliasing")

file(GLOB RecompiledFiles *.cpp)
add_library(PowerSample ${RecompiledFiles})

target_precompile_headers(PowerSample PUBLIC "ppc_recomp_shared.h")

target_link_libraries(PowerSample PUBLIC PowerUtils)
