project("XenonSample")

add_compile_options(
    "/D_HAS_EXCEPTIONS=0"
    "/fp:strict"
    "/GS-"
    "/EHa-"
    "-march=sandybridge"
    "-fno-strict-aliasing")

file(GLOB RecompiledFiles *.cpp)
add_library(XenonSample ${RecompiledFiles})

target_precompile_headers(XenonSample PUBLIC "ppc_recomp_shared.h")
