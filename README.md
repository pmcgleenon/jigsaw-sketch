# Jigsaw Sketch

An implementation of the Jigsaw Sketch algorithm for finding top-k elephant flows in high-speed networks

## Algorithm Overview

The Jigsaw Sketch is a probabilistic data structure that combines the space efficiency of sketches with the accuracy of heavy-hitter algorithms. Key features:

- Space-efficient: Uses compressed counters and fingerprints
- Accurate: Provides accurate frequency estimates for heavy hitters
- Fast: Significantly faster than similar algorithms, e.g. HeavyKeeper
- Reversible: Can reconstruct original keys for heavy flows

The sketch maintains two types of cells:
1. Heavy cells: Store both frequency counts and partial key information
2. Light cells: Store only frequency counts for efficiency

## Paper Reference

For more details, see the original paper:
["Jigsaw-Sketch: a fast and accurate algorithm for finding top-k elephant flows in high-speed networks"](http://scis.scichina.com/en/2024/142101.pdf) by Boyu ZHANG, He HUANG, Yu-E SUN, Yang DU & Dan WANG


## Requirements

- CMake (3.10 or higher)
- C++17 compatible compiler
- Linux/macOS

## Building

1. Create a build directory:
```
mkdir build
cd build
```

2. Setup CMake
```
cmake ..
```

3. Build
```
make
```

4. Download IPv4 data files

The project requires test data files for running examples and benchmarks. See the [data/README.md](data/README.md) for detailed instructions on downloading the test data files and information about the data format.

5. Run examples

Simple word_count example:

```
cd build
./examples/word_count ../data/war_and_peace.txt
```

IPv4 5-tuple example:
```
./examples/flow_processor
```


6. Run benchmarks:

```
cd build
./bench/sketch_bench
```
