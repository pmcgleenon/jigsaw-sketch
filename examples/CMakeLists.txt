# Add flow processor example
add_executable(flow_processor 
    flow_processor.cpp
)

target_include_directories(flow_processor PRIVATE 
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(flow_processor PRIVATE 
    jigsaw
)

# Add word count example
add_executable(word_count 
    word_count.cpp
)

target_include_directories(word_count PRIVATE 
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(word_count PRIVATE 
    jigsaw
)

# Add debug info and optimization flags for both examples
target_compile_options(flow_processor PRIVATE 
    -O3 
    -march=native
    -g 
    -fno-omit-frame-pointer
)

target_compile_options(word_count PRIVATE 
    -O3 
    -march=native
    -g 
    -fno-omit-frame-pointer
) 