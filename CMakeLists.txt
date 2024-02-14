# cmake -S . -B build
# cmake --build build

option(ENABLE_TIDY "Build with tidy checks" ON)
option(BUILD_MAIN "Build main file" ON)

cmake_minimum_required(VERSION 3.10)
project(hw1 LANGUAGES C CXX)
find_package(GTest REQUIRED)

if (ENABLE_TIDY)
  set(CMAKE_CXX_CLANG_TIDY
  clang-tidy;
  -checks=-*,clang-analyzer-*,-clang-analyzer-cplusplus*,bugprone-*,performance-*,readability-*,misc-*,-bugprone-easily-swappable-parameters,-bugprone-suspicious-include,-readability-magic-numbers,-readability-duplicate-include,
  -header-filter=${CMAKE_CURRENT_SOURCE_DIR};
  )
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 14)
add_library(common INTERFACE)
target_compile_options(common INTERFACE -gdwarf-4 -Wall -Wextra -Wshadow -Wpedantic -Wdouble-promotion -Wformat=2 -Wundef -Werror)

if (BUILD_MAIN)
  add_executable(hw1_main src/hw1.c src/hw1_main.c)
  target_link_libraries(hw1_main PRIVATE m)
  target_include_directories(hw1_main PUBLIC include)
endif()

# Build a single executable with all the tests. 
file(GLOB SOURCES tests/src/tests_*.cpp)
add_executable(run_all_tests ${SOURCES} src/hw1.c)
target_include_directories(run_all_tests PUBLIC include tests/include)
target_link_libraries(run_all_tests PRIVATE gtest gtest_main pthread m)

# Build standalone executables to test packetize_array_sf through Valgrind.
set(TARGETS "01" "02" "03" "04")
foreach(TARGET IN LISTS TARGETS)
  add_executable(packetize_array_sf${TARGET}_valgrind tests/src/packetize_array_sf${TARGET}_valgrind.c src/hw1.c)
  target_link_libraries(packetize_array_sf${TARGET}_valgrind PRIVATE m)
  target_include_directories(packetize_array_sf${TARGET}_valgrind PUBLIC include tests/include)
endforeach()

# Build standalone executables to test reconstruct_array_sf through Valgrind.
set(TARGETS "01" "02" "03" "04" "05")
foreach(TARGET IN LISTS TARGETS)
  add_executable(reconstruct_array_sf${TARGET}_valgrind tests/src/reconstruct_array_sf${TARGET}_valgrind.c src/hw1.c)
  target_link_libraries(reconstruct_array_sf${TARGET}_valgrind PRIVATE m)
  target_include_directories(reconstruct_array_sf${TARGET}_valgrind PUBLIC include tests/include)
endforeach()
