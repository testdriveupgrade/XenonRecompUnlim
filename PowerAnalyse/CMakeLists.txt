# cmake_minimum_required (VERSION 3.16)

project("PowerAnalyse")

add_executable(PowerAnalyse "main.cpp" "function.h"  "function.cpp")
target_link_libraries(PowerAnalyse PRIVATE PowerUtils)
