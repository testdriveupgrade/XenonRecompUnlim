# cmake_minimum_required (VERSION 3.16)

project("PowerAnalyse")

add_executable(PowerAnalyse "main.cpp" "function.h"  "function.cpp")
add_library(LibPowerAnalyse "function.h"  "function.cpp")

find_package(fmt CONFIG REQUIRED)

target_include_directories(LibPowerAnalyse PUBLIC .)
target_link_libraries(LibPowerAnalyse PUBLIC PowerUtils)

target_link_libraries(PowerAnalyse PRIVATE PowerUtils fmt::fmt)
