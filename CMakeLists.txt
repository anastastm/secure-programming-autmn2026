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
    set(SODIUM_TARGET unofficial-sodium::sodium)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
    set(SODIUM_TARGET PkgConfig::SODIUM)
endif()
target_link_libraries(password_manager PRIVATE ${SODIUM_TARGET})

if(WIN32)
    target_link_libraries(password_manager PRIVATE advapi32)
endif()

if(MSVC)
    target_compile_options(password_manager PRIVATE /W4)
else()
    target_compile_options(password_manager PRIVATE -Wall -Wextra -Wpedantic)
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(input_validation_tests tests/input_validation_tests.cpp)
    target_include_directories(input_validation_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(input_validation_tests PRIVATE ${SODIUM_TARGET})
    add_test(NAME input_validation COMMAND input_validation_tests)

    add_executable(secret_cleanup_tests tests/secret_cleanup_tests.cpp)
    target_include_directories(secret_cleanup_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(secret_cleanup_tests PRIVATE ${SODIUM_TARGET})
    add_test(NAME secret_cleanup COMMAND secret_cleanup_tests)

    add_executable(security_controls_tests tests/security_controls_tests.cpp)
    target_include_directories(security_controls_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(security_controls_tests PRIVATE ${SODIUM_TARGET})
    add_test(NAME security_controls COMMAND security_controls_tests)
endif()
