#include <cstdint>
#include <iostream>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <chrono>
#include <jigsaw/sketch.hpp>
#include <iomanip>
#include <unordered_map>
#include <vector>

class WordCounter {
private:
    static constexpr uint32_t BUCKET_NUM = 1024;
    static constexpr uint32_t LEFT_PART_BITS = 104;
    static constexpr uint32_t CELL_NUM_H = 8;
    static constexpr uint32_t CELL_NUM_L = 8;
    static constexpr size_t BATCH_SIZE = 1024;  // Match main.rs batch size
    
    // Use CompactStringKey instead of StringKey
    jigsaw::Sketch<jigsaw::CompactStringKey, BUCKET_NUM, LEFT_PART_BITS, CELL_NUM_H, CELL_NUM_L> sketch_;
    std::unordered_map<std::string, uint64_t> actual_counts_;
    bool calculate_actual_;

    inline bool is_whitespace(char c) const {
        return c == ' ' || c == '\n';  // Match main.rs whitespace definition
    }

public:
    explicit WordCounter(bool calculate_actual = false) : calculate_actual_(calculate_actual) {}

    void process_file(const char* filename) {
        int fd = open(filename, O_RDONLY);
        if (fd == -1) {
            throw std::runtime_error("Failed to open file");
        }

        struct stat sb;
        if (fstat(fd, &sb) == -1) {
            close(fd);
            throw std::runtime_error("Failed to get file size");
        }

        const char* data = static_cast<const char*>(
            mmap(nullptr, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0));
        if (data == MAP_FAILED) {
            close(fd);
            throw std::runtime_error("Failed to mmap file");
        }

        const char* end = data + sb.st_size;
        const char* p = data;
        size_t total_words = 0;
        char word_buffer[256];
        
        auto start_time = std::chrono::high_resolution_clock::now();

        while (p < end) {
            // Skip whitespace - direct comparison is faster than isspace()
            while (p < end && (*p == ' ' || *p == '\n' || *p == '\t' || *p == '\r')) {
                p++;
            }
            if (p >= end) break;

            // Found start of word
            const char* word_start = p;
            
            // Find end of word - scan until next whitespace
            while (p < end && !(*p == ' ' || *p == '\n' || *p == '\t' || *p == '\r')) {
                p++;
            }
            
            // Process word
            size_t word_len = p - word_start;
            if (word_len > 0 && word_len < 255) {
                // Copy and convert to uppercase
                for (size_t i = 0; i < word_len; i++) {
                    word_buffer[i] = std::toupper(word_start[i]);
                }
                word_buffer[word_len] = '\0';
                
                // Create CompactStringKey first
                jigsaw::CompactStringKey key(word_buffer);
                
                // Update sketch count
                sketch_.insert(key);

                // Only update actual counts if requested
                if (calculate_actual_) {
                    std::string word = key.to_string();
                    actual_counts_[word]++;
                }
                total_words++;
            }
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

        munmap(const_cast<char*>(data), sb.st_size);
        close(fd);

        std::cout << "Processed " << total_words << " words in " 
                  << duration.count() << "ms\n"
                  << "Throughput: " << (total_words * 1000.0 / duration.count()) 
                  << " words/second\n";

        print_top_words();
    }

    void print_top_words() const {
        auto flows = sketch_.get_heavy_flows();
        std::cout << "Top 10 most frequent words:\n";
        
        if (calculate_actual_) {
            std::cout << std::string(50, '-') << '\n'
                      << std::left << std::setw(20) << "Word"
                      << std::right << std::setw(15) << "Sketch" 
                      << std::right << std::setw(15) << "Actual" << '\n'
                      << std::string(50, '-') << '\n';
        } else {
            std::cout << std::string(35, '-') << '\n'
                      << std::left << std::setw(20) << "Word"
                      << std::right << std::setw(15) << "Count" << '\n'
                      << std::string(35, '-') << '\n';
        }
        
        size_t count = 0;
        for (const auto& flow : flows) {
            if (count++ >= 10) break;
            
            if (calculate_actual_) {
                auto actual_it = actual_counts_.find(flow.key.to_string());
                uint64_t actual_count = actual_it != actual_counts_.end() ? actual_it->second : 0;
                std::cout << std::left << std::setw(20) << flow.key.to_string()
                          << std::right << std::setw(15) << flow.count
                          << std::right << std::setw(15) << actual_count << '\n';
            } else {
                std::cout << std::left << std::setw(20) << flow.key.to_string()
                          << std::right << std::setw(15) << flow.count << '\n';
            }
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2 || argc > 3) {
        std::cerr << "Usage: " << argv[0] << " <input_file> [-a]\n";
        std::cerr << "  -a: calculate actual counts (optional)\n";
        return 1;
    }

    try {
        bool calculate_actual = (argc == 3 && std::string(argv[2]) == "-a");
        WordCounter counter(calculate_actual);
        counter.process_file(argv[1]);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    return 0;
} 