cmake_minimum_required(VERSION 3.14)
project(jigsaw VERSION 1.0.0 LANGUAGES C CXX)

# Set C++17 as minimum
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler options
if(MSVC)
    add_compile_options(/W4 /arch:AVX2)
else()
    add_compile_options(-Wall -Wextra -mavx2 -march=native)
endif()

# Default to Release build if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Add XXHash
include(FetchContent)
FetchContent_Declare(
    xxhash
    GIT_REPOSITORY https://github.com/Cyan4973/xxHash.git
    GIT_TAG v0.8.2
)
FetchContent_MakeAvailable(xxhash)

# Build XXHash as a static library
add_library(xxhash_static STATIC
    ${xxhash_SOURCE_DIR}/xxhash.c
)
target_include_directories(xxhash_static PUBLIC ${xxhash_SOURCE_DIR})

# Header-only library target
add_library(jigsaw INTERFACE)
target_include_directories(jigsaw INTERFACE 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(jigsaw INTERFACE xxhash_static)

# Optional components
option(JIGSAW_BUILD_TESTS "Build tests" ON)
option(JIGSAW_BUILD_BENCHMARKS "Build benchmarks" ON)
option(JIGSAW_BUILD_EXAMPLES "Build examples" ON)

if(JIGSAW_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(JIGSAW_BUILD_BENCHMARKS)
    add_subdirectory(bench)
endif()

if(JIGSAW_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif() 

# Set optimization flags for Release build
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")

# Set debug flags for Debug build
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")
# Enable address sanitizer (optional but helpful)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address -fno-omit-frame-pointer")

# Add architecture-specific optimizations for x86_64
if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
endif()

