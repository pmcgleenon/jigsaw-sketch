#pragma once
#include <cstddef>

namespace jigsaw {

struct Config {
    static constexpr size_t KEY_SIZE = 32;  // Large enough for IPv6 by default
    static constexpr uint32_t MASK_26BITS = 0x3FFFFFF;
    static constexpr unsigned int EXTRA_BITS_NUM = 2;
    
    // Move these constants from Sketch to Config
    static constexpr uint64_t MI_A = 2147483647;
    static constexpr uint64_t MI_A_INV = 4503597479886847;
    static constexpr uint64_t MI_MASK = 4503599627370495;
};

} // namespace jigsaw 