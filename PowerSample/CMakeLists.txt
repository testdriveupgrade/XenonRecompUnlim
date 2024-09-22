project("PowerSample")

add_compile_options(
    "/arch:AVX"
    "/fp:strict"
    "-Wno-unused-label"
    "-Wno-unused-variable")

file(GLOB RecompiledFiles *.cpp)
add_library(PowerSample ${RecompiledFiles})

target_precompile_headers(PowerSample PUBLIC "ppc_recomp_shared.h")

target_link_libraries(PowerSample PUBLIC PowerUtils)
