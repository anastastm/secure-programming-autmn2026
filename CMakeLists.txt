cmake_minimum_required(VERSION 3.16)
project(password_manager LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(password_manager main.cpp)

# vcpkg provides this CMake package on Windows. Linux distributions commonly
# provide libsodium through pkg-config (for example, libsodium-dev on Debian).
find_package(unofficial-sodium CONFIG QUIET)
if(TARGET unofficial-sodium::sodium)
    target_link_libraries(password_manager PRIVATE unofficial-sodium::sodium)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
    target_link_libraries(password_manager PRIVATE PkgConfig::SODIUM)
endif()

if(MSVC)
    target_compile_options(password_manager PRIVATE /W4)
else()
    target_compile_options(password_manager PRIVATE -Wall -Wextra -Wpedantic)
endif()
