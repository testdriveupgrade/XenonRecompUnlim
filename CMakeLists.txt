cmake_minimum_required (VERSION 3.20)
set(THIRDPARTY_ROOT ${CMAKE_SOURCE_DIR}/thirdparty)
set(CMAKE_CXX_STANDARD 23)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_subdirectory(${THIRDPARTY_ROOT}/capstone)
include_directories(${THIRDPARTY_ROOT}/capstone/include)

project ("PowerRecomp-ALL")

add_subdirectory(PowerAnalyse)
add_subdirectory(PowerRecomp)
add_subdirectory(PowerUtils)