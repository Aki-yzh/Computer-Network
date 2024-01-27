cmake_policy(SET CMP0048 NEW)

project(lab3)
cmake_minimum_required(VERSION 3.11)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

set(SRC_FILES router.cpp)

add_library(router STATIC ${SRC_FILES})
find_library(LIB_SIMULATOR simulator build/)

add_executable(simulator simulator.cpp)
target_link_libraries(simulator ${LIB_SIMULATOR} router)