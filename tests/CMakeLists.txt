include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

add_executable(sketch_test test_sketch.cpp)
target_link_libraries(sketch_test 
    PRIVATE 
    jigsaw
    xxhash_static
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(sketch_test) 