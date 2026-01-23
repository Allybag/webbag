cmake_minimum_required(VERSION 3.22)
project(webbag)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(src)
include_directories(SYSTEM external)
add_subdirectory(external SYSTEM)
link_libraries(seaplane)

add_subdirectory(src)
