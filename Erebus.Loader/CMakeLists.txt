cmake_minimum_required(VERSION 3.16)
project(ErebusLoader C CXX)

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_C_COMPILER   x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER  x86_64-w64-mingw32-windres)

set(SRC_DIR      ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(INC_DIR      ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(PAYLOAD_OUT  ${CMAKE_CURRENT_SOURCE_DIR}/payload)

file(GLOB_RECURSE SOURCES ${SRC_DIR}/*.c ${SRC_DIR}/*.cpp ${SRC_DIR}/*.asm)
include_directories(${INC_DIR})

enable_language(C ASM_MASM)

add_executable(erebus_loader WIN32 ${SOURCES})
set_target_properties(erebus_loader PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${PAYLOAD_OUT}
    OUTPUT_NAME "erebus_loader"
    SUFFIX ".exe"
)

target_sources(erebus_loader PRIVATE Erebus.Loader.rc)
