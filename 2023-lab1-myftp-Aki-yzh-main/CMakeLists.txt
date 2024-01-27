project(2023-lab1-myFTP)
cmake_minimum_required(VERSION 3.22)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)


add_executable(ftp_server ftp_server.cpp)
add_executable(ftp_client ftp_client.cpp)