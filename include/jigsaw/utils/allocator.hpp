#pragma once
#include <memory>
#include <cstddef>

namespace jigsaw {

template <typename T, std::size_t Alignment>
class AlignedAllocator {
public:
    using value_type = T;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using propagate_on_container_move_assignment = std::true_type;
    using is_always_equal = std::true_type;

    // Required rebind structure
    template <typename U>
    struct rebind {
        using other = AlignedAllocator<U, Alignment>;
    };
    
    AlignedAllocator() noexcept = default;
    
    template <typename U>
    AlignedAllocator(const AlignedAllocator<U, Alignment>&) noexcept {}

    pointer allocate(size_type n) {
        if (n > std::numeric_limits<size_type>::max() / sizeof(T)) {
            throw std::bad_alloc();
        }
        
        if (auto ptr = std::aligned_alloc(Alignment, n * sizeof(T))) {
            return static_cast<T*>(ptr);
        }
        throw std::bad_alloc();
    }

    void deallocate(pointer p, size_type) noexcept {
        std::free(p);
    }

    // Required comparison operators
    bool operator==(const AlignedAllocator&) const noexcept { return true; }
    bool operator!=(const AlignedAllocator&) const noexcept { return false; }
};

} // namespace jigsaw 