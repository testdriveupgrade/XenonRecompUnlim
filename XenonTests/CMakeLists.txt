project("XenonTests")

add_compile_options(
    "-march=x86-64-v3"
    "-Wno-unused-label"
    "-Wno-unused-variable")

file(GLOB TestFiles *.cpp)

if(TestFiles)
    add_executable(XenonTests ${TestFiles})
    target_link_libraries(XenonTests PUBLIC XenonUtils)
endif()
