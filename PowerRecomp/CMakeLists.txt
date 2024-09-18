cmake_minimum_required (VERSION 3.8)

project("PowerRecomp")

add_executable(PowerRecomp "main.cpp")
target_link_libraries(PowerRecomp PRIVATE LibPowerAnalyse tomlplusplus::tomlplusplus)
