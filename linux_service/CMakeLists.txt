cmake_minimum_required(VERSION 3.10)

project(safe_duck)

set(CMAKE_BUILD_TYPE Debug)

add_executable(safe_duck safe_duck.cpp msg.cpp tools.cpp global.cpp ip_blacktable.cpp events/network.cpp sqlite/sqlite3.c)
