#include <jigsaw/sketch.hpp>
#include <vector>
#include <iostream>
#include <stdexcept>

int main() {
    try {
        // Create sketch with power-of-2 bucket count and cell counts multiple of 16
        jigsaw::Sketch<1024, 26, 16, 16> sketch;  // Note: Changed cell counts to be multiple of 16
        
        // Example data
        std::vector<uint8_t> data = {1, 2, 3, 4, 5};
        
        // Insert and query with bounds checking
        sketch.insert(data.data(), data.size());
        auto freq = sketch.query(data.data(), data.size());
        
        std::cout << "Frequency: " << freq << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
} 