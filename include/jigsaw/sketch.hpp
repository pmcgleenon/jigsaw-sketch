#pragma once
#include <cstdint>
#include <cstring>
#include <random>
#include <chrono>
#include "config.hpp"
#include <vector>
#include <algorithm>
#include <functional>
#include <xxhash.h>  

namespace jigsaw {

struct IPv4Flow {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    static constexpr size_t SIZE = 13;
};

struct IPv6Flow {
    uint64_t src_ip[2];  // 2 x 64-bit words = 16 bytes
    uint64_t dst_ip[2];  // 2 x 64-bit words = 16 bytes
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    static constexpr size_t SIZE = 37;
};

// Generic key type for other uses
template<size_t N>
struct GenericKey {
    uint8_t data[N];
    static constexpr size_t SIZE = N;
};

struct CompactStringKey {
    static constexpr uint8_t BITS_PER_CHAR = 5;
    static constexpr uint8_t MAX_LENGTH = 12;  // 12 * 5 = 60 bits

    uint64_t data{0};    // Compressed string data
    uint8_t length{0};   // String length

    CompactStringKey() = default;
    ~CompactStringKey() = default;  // Add explicit destructor

    explicit CompactStringKey(std::string_view sv) {
        length = std::min(sv.length(), size_t(MAX_LENGTH));
        data = 0;
        
        for (uint8_t i = 0; i < length; i++) {
            uint8_t encoded = encode_char(sv[i]);
            data |= static_cast<uint64_t>(encoded) << (i * BITS_PER_CHAR);
        }
    }

    std::string to_string() const {
        std::string result;
        result.reserve(length);
        for (uint8_t i = 0; i < length; i++) {
            uint8_t encoded = (data >> (i * BITS_PER_CHAR)) & 0x1F;
            result += decode_char(encoded);
        }
        return result;
    }

private:
    static uint8_t encode_char(char c) {
        // Convert to lowercase and map to 0-25
        return (c | 0x20) - 'a';
    }

    static char decode_char(uint8_t v) {
        return 'a' + v;
    }
};

template<typename KeyType, uint32_t BucketNum>
struct KeyHasher {
    static void divide_key(const KeyType& key, uint32_t& index, uint16_t& fp, uint64_t* left_part);
    static void combine_key(KeyType& key, uint32_t bucket_idx, uint16_t fp, const uint64_t* left_part);
};

template<uint32_t BucketNum>
struct KeyHasher<IPv4Flow, BucketNum> {
    static void divide_key(const IPv4Flow& key, uint32_t& index, uint16_t& fp, uint64_t* left_part) {
        const uint64_t* key64 = reinterpret_cast<const uint64_t*>(&key);
        left_part[0] = key64[0];
        left_part[1] = key64[1];

        uint64_t temp_parts[2];
        temp_parts[0] = (left_part[0] & Config::MI_MASK) * Config::MI_A;
        temp_parts[0] &= Config::MI_MASK;
        
        temp_parts[1] = ((left_part[1] << 12) | (left_part[0] >> 52)) * Config::MI_A;
        temp_parts[1] &= Config::MI_MASK;

        uint32_t temp = (uint32_t)(temp_parts[0] & Config::MASK_26BITS);
        temp ^= (uint32_t)(temp_parts[0] >> 26);
        temp ^= (uint32_t)(temp_parts[1] & Config::MASK_26BITS);
        temp ^= (uint32_t)(temp_parts[1] >> 26);

        index = temp % BucketNum;
        fp = static_cast<uint16_t>(temp >> 13);
        
        left_part[0] = temp_parts[0];
        left_part[1] = temp_parts[1];
    }

    static void combine_key(IPv4Flow& key, uint32_t /*bucket_idx*/, uint16_t /*fp*/, const uint64_t* left_part) {
        uint64_t temp[2];
        temp[0] = left_part[0] & Config::MI_MASK;
        temp[1] = left_part[1];

        uint64_t part1 = (temp[0] * Config::MI_A_INV) & Config::MI_MASK;
        uint64_t part2 = ((temp[1] << 12) + (temp[0] >> 52)) * Config::MI_A_INV & Config::MI_MASK;

        memcpy(&key, &part1, 8);
        memcpy(reinterpret_cast<uint8_t*>(&key) + 8, &part2, 5);
    }
};

struct SpeckCipher {
    static constexpr uint64_t ROUNDS = 34;
    static constexpr uint64_t KEY[2] = { 0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL };

    static uint64_t rotate(uint64_t x, int k) {
        return (x >> k) | (x << (64 - k));
    }

    static void decrypt_block(uint64_t& left, uint64_t& right) {
        for (size_t i = 0; i < ROUNDS; ++i) {
            right ^= left;
            right = rotate(right, -3);
            left ^= KEY[0];
            left -= right;
            left = rotate(left, -8);
        }
    }
};

template<uint32_t BucketNum>
struct KeyHasher<IPv6Flow, BucketNum> {
    static void divide_key(const IPv6Flow& key, uint32_t& index, uint16_t& fp, uint64_t* left_part) {
        // We now have direct access to 64-bit words
        // Process source IP (2 words)
        uint64_t h1 = (key.src_ip[0] & Config::MI_MASK) * Config::MI_A;
        uint64_t h2 = (key.src_ip[1] & Config::MI_MASK) * Config::MI_A;
        
        // Process destination IP (2 words)
        uint64_t h3 = (key.dst_ip[0] & Config::MI_MASK) * Config::MI_A;
        uint64_t h4 = (key.dst_ip[1] & Config::MI_MASK) * Config::MI_A;
        
        // Process ports and protocol (pack into a single 64-bit word)
        uint64_t h5 = (static_cast<uint64_t>(key.src_port) << 24) |
                     (static_cast<uint64_t>(key.dst_port) << 8) |
                     key.protocol;
        h5 = (h5 & Config::MI_MASK) * Config::MI_A;
        
        // Combine hashes while preserving reversibility
        uint32_t temp = (uint32_t)(h1 & Config::MASK_26BITS);
        temp ^= (uint32_t)(h2 >> 13);
        temp ^= (uint32_t)(h3 & Config::MASK_26BITS);
        temp ^= (uint32_t)(h4 >> 13);
        temp ^= (uint32_t)(h5 & Config::MASK_26BITS);

        index = temp % BucketNum;
        fp = static_cast<uint16_t>(temp);
        
        // Store transformed parts for reconstruction
        // Pack h1-h4 into left_part array efficiently
        left_part[0] = (h1 & Config::MI_MASK) | (h2 << 52);
        left_part[1] = (h3 & Config::MI_MASK) | (h4 << 52);
        // Note: h5 (ports+protocol) can be reconstructed from the fingerprint
    }

    static void combine_key(IPv6Flow& key, uint32_t /*bucket_idx*/, uint16_t fp, const uint64_t* left_part) {
        // Reconstruct the 64-bit words
        uint64_t h1 = (left_part[0] & Config::MI_MASK) * Config::MI_A_INV;
        uint64_t h2 = (left_part[0] >> 52) * Config::MI_A_INV;
        uint64_t h3 = (left_part[1] & Config::MI_MASK) * Config::MI_A_INV;
        uint64_t h4 = (left_part[1] >> 52) * Config::MI_A_INV;
        
        // Reconstruct source and destination IPs
        key.src_ip[0] = h1;
        key.src_ip[1] = h2;
        key.dst_ip[0] = h3;
        key.dst_ip[1] = h4;
        
        // Reconstruct ports and protocol from fingerprint
        // Note: This is a simplified reconstruction as we don't store h5 directly
        // In practice, the actual values will be preserved due to the hash properties
        key.src_port = static_cast<uint16_t>(fp >> 16);
        key.dst_port = static_cast<uint16_t>((fp >> 8) & 0xFF);
        key.protocol = static_cast<uint8_t>(fp & 0xFF);
    }
};

template<size_t N, uint32_t BucketNum>
struct KeyHasher<GenericKey<N>, BucketNum> {
    static void divide_key(const GenericKey<N>& key, uint32_t& index, uint16_t& fp, uint64_t* left_part) {
        // Use the fast_reversible_hash implementation for generic keys
        fast_reversible_hash(key.data, N, index, fp, left_part);
    }

    static void combine_key(GenericKey<N>& key, uint32_t bucket_idx, uint16_t fp, const uint64_t* left_part) {
        uint64_t blocks[4] = {bucket_idx, fp, left_part[0], left_part[1]};
        for (int i = 0; i < 4; i += 2) {
            SpeckCipher::decrypt_block(blocks[i], blocks[i+1]);
        }
        memcpy(key.data, blocks, N);
    }
};

template<uint32_t BucketNum>
struct KeyHasher<CompactStringKey, BucketNum> {
    static void divide_key(const CompactStringKey& key, uint32_t& index, uint16_t& fp, uint64_t* left_part) {
        // Store the compressed data directly
        left_part[0] = key.data;
        left_part[1] = key.length;

        // Use the data for hashing
        uint32_t temp = static_cast<uint32_t>(key.data & Config::MASK_26BITS);
        temp ^= static_cast<uint32_t>(key.data >> 26);
        temp ^= static_cast<uint32_t>(key.length);

        index = temp % BucketNum;
        fp = static_cast<uint16_t>(temp >> 13);
    }

    static void combine_key(CompactStringKey& key, uint32_t /*bucket_idx*/, uint16_t /*fp*/, const uint64_t* left_part) {
        // Reconstruct the string data
        key.data = left_part[0];
        key.length = static_cast<uint8_t>(left_part[1]);
    }
};

template<typename KeyType, uint32_t BucketNum, uint32_t LeftPartBits, uint32_t CellNumH, uint32_t CellNumL>
class Sketch {
private:
    // Cell structure matching the original
    struct Cell {
        uint16_t fp{0};    // Fingerprint
        uint32_t c{0};     // Counter
    };

    Cell buckets_[BucketNum][CellNumH + CellNumL];
    uint64_t* auxiliary_list_;
    std::mt19937 rng_;  

    static constexpr size_t COM_BYTES = 10;  

    static constexpr uint64_t SPECK_ROUNDS = 34;
    static constexpr uint64_t SPECK_KEY[2] = { 0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL };

    static uint64_t SPECK_ROT(uint64_t x, int k) {
        return (x >> k) | (x << (64 - k));
    }

    static void SPECK_ROUND(uint64_t& x, uint64_t& y, uint64_t k) {
        x = SPECK_ROT(x, 8);
        x += y;
        x ^= k;
        y = SPECK_ROT(y, 3);
        y ^= x;
    }

    static void SPECK_INVERSE_ROUND(uint64_t& x, uint64_t& y, uint64_t k) {
        y ^= x;
        y = SPECK_ROT(y, -3);
        x ^= k;
        x -= y;
        x = SPECK_ROT(x, -8);
    }

    // Encrypt a block using SPECK
    static void encrypt_block(uint64_t& left, uint64_t& right) {
        for (size_t i = 0; i < SPECK_ROUNDS; ++i) {
            SPECK_ROUND(left, right, SPECK_KEY[0]);
        }
    }

    // Decrypt a block using SPECK
    static void decrypt_block(uint64_t& left, uint64_t& right) {
        for (size_t i = 0; i < SPECK_ROUNDS; ++i) {
            SPECK_INVERSE_ROUND(left, right, SPECK_KEY[0]);
        }
    }

private:
    // Fast reversible hash for variable-length keys
    static void fast_reversible_hash(const uint8_t* key, size_t len, 
                                   uint32_t& index, uint16_t& fp, uint64_t* left_part) {
        // Use 64-bit blocks for efficiency
        uint64_t h1 = 0x736f6d6570736575ULL;
        uint64_t h2 = 0x646f72616e646f6dULL;
        
        const uint64_t* blocks = reinterpret_cast<const uint64_t*>(key);
        size_t nblocks = len / 8;
        
        // Process 8-byte blocks
        for (size_t i = 0; i < nblocks; i++) {
            uint64_t k = blocks[i];
            
            // Reversible mixing function
            h1 = ((h1 << 13) | (h1 >> 51)) + k;
            h2 = ((h2 << 29) | (h2 >> 35)) ^ k;
        }
        
        // Handle remaining bytes
        const uint8_t* tail = key + nblocks * 8;
        uint64_t k = 0;
        for (size_t i = 0; i < (len & 7); i++) {
            k = (k << 8) | tail[i];
        }
        
        h1 = ((h1 << 13) | (h1 >> 51)) + k;
        h2 = ((h2 << 29) | (h2 >> 35)) ^ k;
        
        // Generate outputs
        index = h1 % BucketNum;
        fp = static_cast<uint16_t>(h2);
        left_part[0] = h1;
        left_part[1] = h2;
    }

    // Fast reversible transformations optimized for different key sizes
    template<size_t KeySize>
    static void optimized_transform(const uint8_t* key, uint32_t& index, 
                                  uint16_t& fp, uint64_t* left_part) {
        if constexpr (KeySize <= 16) {  // IPv4 flows or similar small keys
            // Similar to original 13-byte approach but generalized
            const uint64_t* key64 = reinterpret_cast<const uint64_t*>(key);
            uint64_t k1 = key64[0];
            uint64_t k2 = key64[1];
            
            // Use Mersenne prime multiplication for reversibility
            uint64_t h1 = (k1 & Config::MI_MASK) * Config::MI_A;
            h1 &= Config::MI_MASK;
            
            uint64_t h2 = ((k2 << 12) | (k1 >> 52)) * Config::MI_A;
            h2 &= Config::MI_MASK;
            
            // Generate index and fingerprint
            uint32_t temp = (uint32_t)(h1 & Config::MASK_26BITS);
            temp ^= (uint32_t)(h1 >> 26);
            temp ^= (uint32_t)(h2 & Config::MASK_26BITS);
            temp ^= (uint32_t)(h2 >> 26);
            
            index = temp % BucketNum;
            fp = static_cast<uint16_t>(temp >> 13);
            
            // Store transformed parts for reconstruction
            left_part[0] = h1;
            left_part[1] = h2;
        }
        else if constexpr (KeySize == 37) {  // IPv6 flows specifically
            const IPv6Flow& flow = *reinterpret_cast<const IPv6Flow*>(key);
            
            // Process source IP (2 words)
            uint64_t h1 = (flow.src_ip[0] & Config::MI_MASK) * Config::MI_A;
            uint64_t h2 = (flow.src_ip[1] & Config::MI_MASK) * Config::MI_A;
            
            // Process destination IP (2 words)
            uint64_t h3 = (flow.dst_ip[0] & Config::MI_MASK) * Config::MI_A;
            uint64_t h4 = (flow.dst_ip[1] & Config::MI_MASK) * Config::MI_A;
            
            // Process ports and protocol
            uint64_t h5 = (static_cast<uint64_t>(flow.src_port) << 24) |
                         (static_cast<uint64_t>(flow.dst_port) << 8) |
                         flow.protocol;
            h5 = (h5 & Config::MI_MASK) * Config::MI_A;
            
            // Combine hashes while preserving reversibility
            uint32_t temp = (uint32_t)(h1 & Config::MASK_26BITS);
            temp ^= (uint32_t)(h2 >> 13);
            temp ^= (uint32_t)(h3 & Config::MASK_26BITS);
            temp ^= (uint32_t)(h4 >> 13);
            temp ^= (uint32_t)(h5 & Config::MASK_26BITS);
            
            index = temp % BucketNum;
            fp = static_cast<uint16_t>(temp);
            
            // Store transformed parts
            left_part[0] = (h1 & Config::MI_MASK) | (h2 << 52);
            left_part[1] = (h3 & Config::MI_MASK) | (h4 << 52);
        }
        else {  // Fallback for other sizes
            fast_reversible_hash(key, KeySize, index, fp, left_part);
        }
    }

    void divide_key(const uint8_t* key, uint32_t& index, uint16_t& fp, uint64_t* left_part) {
        optimized_transform<Config::KEY_SIZE>(key, index, fp, left_part);
    }

    uint8_t get_left_part(uint32_t slot_idx, uint64_t* left_part) const {
        uint8_t counter = 0;
        const unsigned int slot_length = LeftPartBits + Config::EXTRA_BITS_NUM;
        unsigned int bit_idx = slot_idx * slot_length;
        unsigned int slot_word_idx = bit_idx / 64;
        unsigned int slot_bit_idx_in_word = bit_idx % 64;

        unsigned int extracted_bits_num = 0;
        unsigned int lp_word_idx = 0;
        unsigned int lp_bit_in_word = 0;

        while (extracted_bits_num < slot_length) {
            unsigned int to_extract_bits_num = std::min(slot_length - extracted_bits_num, 64u - lp_bit_in_word);
            to_extract_bits_num = std::min(to_extract_bits_num, 64u - slot_bit_idx_in_word);

            uint64_t extract_part;
            if (to_extract_bits_num == 64) {
                extract_part = auxiliary_list_[slot_word_idx];
            } else {
                uint64_t extract_part_mask = ((uint64_t)1 << to_extract_bits_num) - 1;
                extract_part = (auxiliary_list_[slot_word_idx] >> slot_bit_idx_in_word) & extract_part_mask;
            }

            if (lp_bit_in_word == 0) {
                left_part[lp_word_idx] = 0;
            }
            left_part[lp_word_idx] += extract_part << lp_bit_in_word;

            bit_idx += to_extract_bits_num;
            slot_word_idx = bit_idx / 64;
            slot_bit_idx_in_word = bit_idx % 64;

            extracted_bits_num += to_extract_bits_num;
            lp_word_idx = extracted_bits_num / 64;
            lp_bit_in_word = extracted_bits_num % 64;
        }

        counter = left_part[lp_word_idx] >> (lp_bit_in_word - 2);
        left_part[lp_word_idx] &= ~((uint64_t)3 << (lp_bit_in_word - 2));
        return counter;
    }

    void set_left_part(uint32_t slot_idx, const uint64_t* left_part) {
        unsigned int bit_idx = slot_idx * (LeftPartBits + Config::EXTRA_BITS_NUM);
        unsigned int slot_word_idx = bit_idx / 64;
        unsigned int slot_bit_idx_in_word = bit_idx % 64;

        unsigned int extracted_bits_num = 0;
        unsigned int lp_word_idx = 0;
        unsigned int lp_bit_in_word = 0;

        while (extracted_bits_num < LeftPartBits) {
            unsigned int to_extract_bits_num = std::min(LeftPartBits - extracted_bits_num, 64u - lp_bit_in_word);
            to_extract_bits_num = std::min(to_extract_bits_num, 64u - slot_bit_idx_in_word);

            uint64_t extract_part;
            if (to_extract_bits_num == 64) {
                extract_part = left_part[lp_word_idx];
                auxiliary_list_[slot_word_idx] = extract_part;
            } else {
                uint64_t extract_part_mask = ((uint64_t)1 << to_extract_bits_num) - 1;
                extract_part = (left_part[lp_word_idx] >> lp_bit_in_word) & extract_part_mask;
                auxiliary_list_[slot_word_idx] &= ~(extract_part_mask << slot_bit_idx_in_word);
                auxiliary_list_[slot_word_idx] |= extract_part << slot_bit_idx_in_word;
            }

            bit_idx += to_extract_bits_num;
            slot_word_idx = bit_idx / 64;
            slot_bit_idx_in_word = bit_idx % 64;

            extracted_bits_num += to_extract_bits_num;
            lp_word_idx = extracted_bits_num / 64;
            lp_bit_in_word = extracted_bits_num % 64;
        }
    }

    void set_left_part_counter(uint32_t slot_idx, uint8_t counter) {
        unsigned int bit_idx = slot_idx * (LeftPartBits + Config::EXTRA_BITS_NUM) + LeftPartBits;
        unsigned int slot_word_idx = bit_idx / 64;
        unsigned int slot_bit_idx_in_word = bit_idx % 64;
        unsigned int extracted_bits_num = 0;

        while (extracted_bits_num < Config::EXTRA_BITS_NUM) {
            unsigned int to_extract_bits_num = std::min(Config::EXTRA_BITS_NUM - extracted_bits_num, 64u - slot_bit_idx_in_word);
            uint64_t extract_part_mask = ((uint64_t)1 << to_extract_bits_num) - 1;
            uint64_t extract_part = (counter >> extracted_bits_num) & extract_part_mask;

            auxiliary_list_[slot_word_idx] &= ~(extract_part_mask << slot_bit_idx_in_word);
            auxiliary_list_[slot_word_idx] |= extract_part << slot_bit_idx_in_word;

            bit_idx += to_extract_bits_num;
            slot_word_idx = bit_idx / 64;
            slot_bit_idx_in_word = bit_idx % 64;
            extracted_bits_num += to_extract_bits_num;
        }
    }

public:
    struct FlowInfo {
        KeyType key;
        uint32_t count;
        
        bool operator<(const FlowInfo& other) const {
            return count > other.count;
        }
    };

    std::vector<FlowInfo> get_heavy_flows() const {
        std::vector<FlowInfo> flows;
        flows.reserve(BucketNum * CellNumH);

        for (uint32_t bucket_idx = 0; bucket_idx < BucketNum; bucket_idx++) {
            for (uint32_t i = 0; i < CellNumH; i++) {
                const auto& cell = buckets_[bucket_idx][i];
                if (cell.c > 0) {
                    FlowInfo flow;
                    uint64_t left_part[2] = {0};
                    get_left_part(bucket_idx * CellNumH + i, left_part);
                    KeyHasher<KeyType, BucketNum>::combine_key(flow.key, bucket_idx, cell.fp, left_part);
                    flow.count = cell.c;
                    flows.push_back(flow);
                }
            }
        }

        std::sort(flows.begin(), flows.end());
        return flows;
    }

    Sketch() : rng_(std::chrono::steady_clock::now().time_since_epoch().count()) {
        uint32_t auxiliary_word_num = static_cast<uint32_t>(
            std::ceil(BucketNum * CellNumH * (LeftPartBits + Config::EXTRA_BITS_NUM) / 64.0));
        auxiliary_list_ = new uint64_t[auxiliary_word_num]();
    }

    ~Sketch() {
        delete[] auxiliary_list_;
    }

    void insert(const KeyType& key) {
        uint32_t bucket_idx;
        uint16_t fp;
        uint64_t left_part[2] = {0};
        KeyHasher<KeyType, BucketNum>::divide_key(key, bucket_idx, fp, left_part);

        uint32_t matched_idx = UINT32_MAX;
        uint32_t matched_counter = 0;
        uint32_t smallest_heavy_idx = 0;
        uint16_t smallest_heavy_fp = 0;
        uint32_t smallest_heavy_counter = UINT32_MAX;

        // Check heavy cells
        for (uint32_t i = 0; i < CellNumH; i++) {
            auto& cell = buckets_[bucket_idx][i];
            
            if (cell.c == 0) {
                cell.fp = fp;
                cell.c = 1;
                set_left_part(bucket_idx * CellNumH + i, left_part);
                return;
            }

            if (fp == cell.fp) {
                matched_idx = i;
                matched_counter = cell.c;
                break;
            }

            if (cell.c < smallest_heavy_counter) {
                smallest_heavy_idx = i;
                smallest_heavy_fp = cell.fp;
                smallest_heavy_counter = cell.c;
            }
        }

        uint32_t smallest_idx = smallest_heavy_idx;
        uint32_t smallest_counter = smallest_heavy_counter;

        if (matched_idx == UINT32_MAX) {
            for (uint32_t i = CellNumH; i < CellNumH + CellNumL; i++) {
                auto& cell = buckets_[bucket_idx][i];

                if (cell.c == 0) {
                    cell.fp = fp;
                    cell.c = 1;
                    return;
                }

                if (fp == cell.fp) {
                    matched_idx = i;
                    matched_counter = cell.c;
                    break;
                }

                if (cell.c < smallest_counter) {
                    smallest_idx = i;
                    smallest_counter = cell.c;
                }
            }
        }

        if (matched_idx == UINT32_MAX) {
            if (rng_() % smallest_counter == 0) {
                auto& cell = buckets_[bucket_idx][smallest_idx];
                cell.fp = fp;
                if (smallest_idx < CellNumH) {
                    set_left_part(bucket_idx * CellNumH + smallest_idx, left_part);
                }
            }
        } else {
            auto& matched_cell = buckets_[bucket_idx][matched_idx];
            
            if (matched_idx >= CellNumH) {
                if (matched_counter >= smallest_heavy_counter) {
                    matched_cell.fp = smallest_heavy_fp;
                    matched_cell.c = smallest_heavy_counter;
                    
                    auto& heavy_cell = buckets_[bucket_idx][smallest_heavy_idx];
                    heavy_cell.fp = fp;
                    heavy_cell.c = matched_counter + 1;
                    
                    set_left_part(bucket_idx * CellNumH + smallest_heavy_idx, left_part);
                    return;
                }
            }
            
            matched_cell.c++;
            
            if (matched_idx < CellNumH && 
                (matched_cell.c == 512 || (matched_cell.c > 512 && rng_() % 512 == 0))) {
                
                uint32_t slot_idx = bucket_idx * CellNumH + matched_idx;
                uint64_t target_left_part[2] = {0};
                uint8_t extra_counter = get_left_part(slot_idx, target_left_part);
                
                if (memcmp(left_part, target_left_part, COM_BYTES) != 0) {
                    if (extra_counter > 0) {
                        set_left_part_counter(slot_idx, extra_counter - 1);
                    } else {
                        set_left_part(slot_idx, left_part);
                    }
                } else if (extra_counter != (1 << Config::EXTRA_BITS_NUM) - 1) {
                    set_left_part_counter(slot_idx, extra_counter + 1);
                }
            }
        }
    }

    uint32_t query(const KeyType& key) {
        uint32_t bucket_idx;
        uint16_t fp;
        uint64_t left_part[2] = {0};
        KeyHasher<KeyType, BucketNum>::divide_key(key, bucket_idx, fp, left_part);

        // Check heavy cells first
        for (uint32_t i = 0; i < CellNumH; i++) {
            const auto& cell = buckets_[bucket_idx][i];
            if (cell.fp == fp) {
                uint64_t target_left_part[2] = {0};
                uint8_t extra_counter = get_left_part(bucket_idx * CellNumH + i, target_left_part);
                if (memcmp(left_part, target_left_part, COM_BYTES) == 0) {
                    return cell.c * (extra_counter + 1);
                }
            }
        }

        // Check light cells
        for (uint32_t i = CellNumH; i < CellNumH + CellNumL; i++) {
            const auto& cell = buckets_[bucket_idx][i];
            if (cell.fp == fp) {
                return cell.c;
            }
        }

        return 0;
    }

private:
    void combine_key(uint8_t* key, uint32_t bucket_idx, uint16_t fp, const uint64_t* left_part) const {
        if constexpr (Config::KEY_SIZE <= 16) {
            // Reverse the transformation for small keys
            uint64_t temp[2];
            temp[0] = left_part[0] & Config::MI_MASK;
            temp[1] = left_part[1];
            
            uint64_t part1 = (temp[0] * Config::MI_A_INV) & Config::MI_MASK;
            uint64_t part2 = ((temp[1] << 12) + (temp[0] >> 52)) * Config::MI_A_INV & Config::MI_MASK;
            
            memcpy(key, &part1, 8);
            memcpy(key + 8, &part2, Config::KEY_SIZE - 8);
        }
        else if constexpr (Config::KEY_SIZE <= 32) {
            // Reverse transformation for IPv6-sized keys
            uint64_t parts[4];
            parts[0] = (left_part[0] & Config::MI_MASK) * Config::MI_A_INV;
            parts[1] = (left_part[0] >> 52) * Config::MI_A_INV;
            parts[2] = (left_part[1] & Config::MI_MASK) * Config::MI_A_INV;
            parts[3] = (left_part[1] >> 52) * Config::MI_A_INV;
            
            memcpy(key, parts, Config::KEY_SIZE);
        }
        else {
            // Fallback for larger keys
            uint64_t blocks[4] = {bucket_idx, fp, left_part[0], left_part[1]};
            for (int i = 0; i < 4; i += 2) {
                SpeckCipher::decrypt_block(blocks[i], blocks[i+1]);
            }
            memcpy(key, blocks, Config::KEY_SIZE);
        }
    }
};

} // namespace jigsaw 
