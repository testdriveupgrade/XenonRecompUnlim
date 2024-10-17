cmake_minimum_required (VERSION 3.8)

project("PowerRecomp")

BIN2H(SOURCE_FILE ${POWERUTILS_ROOT}/ppc_context.h HEADER_FILE "generated/ppc_context.gen.h" ARRAY_TYPE "char" VARIABLE_NAME "g_PPCContextText")

add_executable(PowerRecomp "main.cpp" "pch.h" "recompiler.cpp" "recompiler.h" "test_recompiler.cpp" "test_recompiler.h" "recompiler_config.h" "recompiler_config.cpp")
target_precompile_headers(PowerRecomp PUBLIC "pch.h")
target_link_libraries(PowerRecomp PRIVATE LibPowerAnalyse tomlplusplus::tomlplusplus xxHash::xxhash)
