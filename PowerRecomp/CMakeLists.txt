cmake_minimum_required (VERSION 3.8)

project("PowerRecomp")

add_executable(PowerRecomp "main.cpp" "pch.h" "recompiler.cpp" "recompiler.h" "swa_recompiler.cpp" "swa_recompiler.h")
target_precompile_headers(PowerRecomp PUBLIC "pch.h")
target_link_libraries(PowerRecomp PRIVATE LibPowerAnalyse tomlplusplus::tomlplusplus xxHash::xxhash)
