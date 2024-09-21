project("PowerTests")

file(GLOB TestFiles *.cpp)
add_executable(PowerTests ${TestFiles})

target_link_libraries(PowerTests PUBLIC PowerUtils)
