cmake_minimum_required (VERSION 3.20)
set(THIRDPARTY_ROOT ${CMAKE_SOURCE_DIR}/thirdparty)
set(CMAKE_CXX_STANDARD 23)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

include(FetchContent)
FetchContent_Declare(
    tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG        v3.4.0
)
FetchContent_Declare(
    xxHash
    GIT_REPOSITORY https://github.com/Cyan4973/xxHash.git
    GIT_TAG        v0.8.2
    SOURCE_SUBDIR "cmake_unofficial"
)
FetchContent_MakeAvailable(tomlplusplus)
FetchContent_MakeAvailable(xxHash)

add_subdirectory(${THIRDPARTY_ROOT}/disasm)

project ("PowerRecomp-ALL")

add_subdirectory(PowerAnalyse)
add_subdirectory(PowerRecomp)
add_subdirectory(PowerUtils)
add_subdirectory(PowerSample)
