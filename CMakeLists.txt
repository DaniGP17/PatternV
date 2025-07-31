cmake_minimum_required(VERSION 3.16)
project(PatternV)

set(CMAKE_CXX_STANDARD 20)

file(GLOB_RECURSE SOURCES "PatternV.cpp")
add_executable(PatternV ${SOURCES})

add_custom_command(TARGET PatternV POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:PatternV>/Builds"
)