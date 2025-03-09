#pragma once
#include <xxhash.h>

namespace jigsaw {

class HashFunction {
private:
    XXH3_state_t* state;

public:
    HashFunction() : state(XXH3_createState()) {}
    ~HashFunction() { XXH3_freeState(state); }

    HashFunction(const HashFunction&) = delete;
    HashFunction& operator=(const HashFunction&) = delete;

    uint64_t operator()(const uint8_t* key, size_t len) const {
        return XXH3_64bits(key, len);
    }

    uint64_t with_seed(const uint8_t* key, size_t len, uint64_t seed) const {
        return XXH3_64bits_withSeed(key, len, seed);
    }
};

} // namespace jigsaw 