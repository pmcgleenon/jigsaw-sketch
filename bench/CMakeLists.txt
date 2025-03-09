include(FetchContent)

FetchContent_Declare(
    googlebenchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG v1.8.3
)
set(BENCHMARK_ENABLE_TESTING OFF)
FetchContent_MakeAvailable(googlebenchmark)

add_executable(sketch_bench bench_sketch.cpp)
target_link_libraries(sketch_bench 
    PRIVATE 
    jigsaw
    benchmark::benchmark
) 