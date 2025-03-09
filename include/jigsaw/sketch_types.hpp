#pragma once
#include "sketch.hpp"

namespace jigsaw {

// Common sketch configurations
using SmallSketch = Sketch<IPv4Flow, 1024, 79, 8, 8>;      // ~16KB memory
using MediumSketch = Sketch<IPv4Flow, 4096, 79, 16, 16>;   // ~128KB memory
using LargeSketch = Sketch<IPv4Flow, 16384, 79, 32, 32>;   // ~1MB memory

// Word counting sketches
using WordSketch = Sketch<CompactStringKey, 1024, 104, 8, 8>;
using LargeWordSketch = Sketch<CompactStringKey, 4096, 104, 16, 16>;

// IPv6 sketches
using IPv6Sketch = Sketch<IPv6Flow, 1024, 79, 8, 8>;
using LargeIPv6Sketch = Sketch<IPv6Flow, 4096, 79, 16, 16>;

// Memory usage calculator
template<typename KeyType, uint32_t BucketNum, uint32_t LeftPartBits, uint32_t CellNumH, uint32_t CellNumL>
constexpr size_t SketchMemoryUsage() {
    // Cell size: fingerprint (2 bytes) + counter (4 bytes)
    constexpr size_t cell_size = 6;
    // Bucket memory
    constexpr size_t bucket_mem = BucketNum * (CellNumH + CellNumL) * cell_size;
    // Auxiliary list memory
    constexpr size_t aux_mem = (BucketNum * CellNumH * (LeftPartBits + Config::EXTRA_BITS_NUM) + 63) / 64 * 8;
    return bucket_mem + aux_mem;
}

} // namespace jigsaw 