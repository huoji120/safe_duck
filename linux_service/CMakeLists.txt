cmake_minimum_required(VERSION 3.10)

project(safe_duck)

# 设置 C++ 标准为 C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 设置构建类型为 Debug
set(CMAKE_BUILD_TYPE Debug)

# 添加可执行文件及源文件
add_executable(safe_duck safe_duck.cpp msg.cpp tools.cpp global.cpp ip_blacktable.cpp events/network.cpp sqlite/sqlite3.c)

# 链接 pthread 库和 dl 库
target_link_libraries(safe_duck pthread dl)
