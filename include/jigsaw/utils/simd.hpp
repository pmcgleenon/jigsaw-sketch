#pragma once
#include <immintrin.h>
#include <array>

namespace jigsaw {
namespace simd {

// Pre-computed comparison mask for 16-bit elements
alignas(32) inline const std::array<uint16_t, 16> comparison_mask = {
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF
};

// SIMD helper functions
inline __m256i load_fingerprints(const void* ptr) {
    if (!ptr) return _mm256_setzero_si256();
    return _mm256_load_si256(reinterpret_cast<const __m256i*>(ptr));
}

inline uint32_t compare_fingerprints(__m256i fps, uint16_t target) {
    __m256i target_vec = _mm256_set1_epi16(target);
    __m256i cmp = _mm256_cmpeq_epi16(fps, target_vec);
    return _mm256_movemask_epi8(cmp);
}

}} // namespace jigsaw::simd 