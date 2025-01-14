cmake_minimum_required (VERSION 3.8)

project("PowerRecomp")

add_executable(PowerRecomp 
    "main.cpp" 
    "recompiler.cpp"
    "test_recompiler.cpp" 
    "recompiler_config.cpp")

target_precompile_headers(PowerRecomp PUBLIC "pch.h")

target_link_libraries(PowerRecomp PRIVATE
    LibPowerAnalyse 
    PowerUtils 
    fmt::fmt
    tomlplusplus::tomlplusplus 
    xxHash::xxhash)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(PowerRecomp PRIVATE -Wno-switch -Wno-unused-variable -Wno-null-arithmetic)
endif()

target_compile_definitions(PowerRecomp PRIVATE _CRT_SECURE_NO_WARNINGS)
