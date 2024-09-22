project("PowerTests")

add_compile_options(
    "-march=x86-64-v3"
    "-Wno-unused-label"
    "-Wno-unused-variable")

file(GLOB TestFiles *.cpp)
add_executable(PowerTests ${TestFiles})
target_link_libraries(PowerTests PUBLIC PowerUtils)
