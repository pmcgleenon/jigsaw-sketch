#pragma once
#include <cstdint>

namespace jigsaw {

#pragma pack(push, 1)
struct Cell {
    uint16_t fingerprint{0};
    uint32_t counter{0};
};
#pragma pack(pop)

static_assert(sizeof(Cell) == 6, "Cell must be 6 bytes");

} // namespace jigsaw 
