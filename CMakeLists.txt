cmake_minimum_required(VERSION 3.10)
project(Nacht VERSION 0.1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(thirdparty/minhook)
add_subdirectory(thirdparty/magic_enum)

add_executable(${PROJECT_NAME} main.cpp offset.cpp)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/)
target_link_libraries(${PROJECT_NAME} PRIVATE minhook magic_enum::magic_enum psapi)