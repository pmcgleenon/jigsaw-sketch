#include <cstdint>
#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <unordered_map>
#include <jigsaw/sketch.hpp>
#include <cstring>
#include <arpa/inet.h>
#include <iomanip>
#include <algorithm>

using namespace std;

// Constants
static constexpr size_t INET_ADDRSTR_SIZE = INET_ADDRSTRLEN;

// Use key size from jigsaw config
struct HashFunc {
    size_t operator()(const uint8_t* key) const {
        return std::hash<std::string_view>{}(
            std::string_view((char*)key, jigsaw::IPv4Flow::SIZE));
    }
};

struct CmpFunc {
    bool operator()(const uint8_t* a, const uint8_t* b) const {
        return memcmp(a, b, jigsaw::IPv4Flow::SIZE) == 0;
    }
};

class TraceProcessor {
public:
    static constexpr size_t kKeySize = jigsaw::Config::KEY_SIZE;
    static constexpr size_t kMaxItems = 40'000'000;

private:
    // Convert from input format to struct format for IPv4
    static void adaptInputToIPv4Flow(const char* input, char* output) {
        // Input format: srcIP(4), srcPort(2), dstIP(4), dstPort(2), proto(1)
        // Output format: srcIP(4), dstIP(4), srcPort(2), dstPort(2), proto(1)
        
        uint32_t src_ip, dst_ip;
        uint16_t src_port, dst_port;
        uint8_t protocol;
        
        // Read values maintaining network byte order
        memcpy(&src_ip, input, 4);
        memcpy(&src_port, input + 4, 2);
        memcpy(&dst_ip, input + 6, 4);
        memcpy(&dst_port, input + 10, 2);
        protocol = input[12];

        // Write in struct layout order, keeping network byte order
        memcpy(output, &src_ip, 4);      // source IP
        memcpy(output + 4, &dst_ip, 4);  // destination IP
        memcpy(output + 8, &src_port, 2);  // source port
        memcpy(output + 10, &dst_port, 2); // destination port
        output[12] = protocol;           // protocol
    }

    size_t readTraces(const std::string& trace_prefix, 
                     std::vector<uint8_t*>& keys,
                     std::unordered_map<uint8_t*, unsigned int, HashFunc, CmpFunc>& flow_sizes) {
        size_t total_count = 0;

        for (int file_num = 0; file_num <= 10; ++file_num) {
            std::string trace_path = trace_prefix + std::to_string(file_num) + ".dat";
            std::cout << "Start reading " << trace_path << '\n';

            FILE* fin = fopen(trace_path.c_str(), "rb");
            if (!fin) {
                std::cerr << "Failed to open " << trace_path << '\n';
                continue;
            }

            size_t file_count = 0;
            char input_buf[jigsaw::IPv4Flow::SIZE];
            char adapted_buf[jigsaw::IPv4Flow::SIZE];

            while (fread(input_buf, 1, jigsaw::IPv4Flow::SIZE, fin) == jigsaw::IPv4Flow::SIZE && 
                   total_count < kMaxItems) {
                
                // Adapt the input format to match our struct layout
                adaptInputToIPv4Flow(input_buf, adapted_buf);

                // Allocate and copy the adapted data
                uint8_t* key = (uint8_t*)malloc(jigsaw::IPv4Flow::SIZE);
                if (!key) {
                    std::cerr << "Memory allocation failed!\n";
                    break;
                }
                memcpy(key, adapted_buf, jigsaw::IPv4Flow::SIZE);

            
                keys.push_back(key);

            
                // Debug the hash map insertion
                auto [it, inserted] = flow_sizes.try_emplace(key, 1);
                if (!inserted) {
                    it->second++;
                }
                
                if (++file_count % 5'000'000 == 0) {
                    std::cout << "\tRead " << file_count << " items from file " 
                             << file_num << ", total: " << total_count << '\n';
                }
                total_count++;
            }
            
            fclose(fin);
            std::cout << "Finished file " << file_num << " (" << file_count 
                     << " items), total: " << total_count << '\n';
        }
        
        return total_count;
    }

    // Protocol number to name mapping
    static const char* getProtocolName(uint8_t protocol) {
        static char unknown_proto[8];  // Buffer for unknown protocol numbers
        
        switch(protocol) {
            case 1: return "ICMP";
            case 6: return "TCP";
            case 17: return "UDP";
            default:
                snprintf(unknown_proto, sizeof(unknown_proto), "%u", protocol);
                return unknown_proto;
        }
    }

    static void printFlow(const uint8_t* key, unsigned int count) {
        const jigsaw::IPv4Flow& flow = *reinterpret_cast<const jigsaw::IPv4Flow*>(key);
        
        // Convert IPs to string representation
        char src_ip[INET_ADDRSTR_SIZE], dst_ip[INET_ADDRSTR_SIZE];
        inet_ntop(AF_INET, &flow.src_ip, src_ip, INET_ADDRSTR_SIZE);
        inet_ntop(AF_INET, &flow.dst_ip, dst_ip, INET_ADDRSTR_SIZE);
        
        std::cout << std::setw(2) << (int)flow.protocol << " "
                 << src_ip << ":" << ntohs(flow.src_port)  // Convert port from network to host for display
                 << " -> " << dst_ip << ":" << ntohs(flow.dst_port)
                 << " " << count << std::endl;
    }

    void printTopFlows(const std::unordered_map<uint8_t*, unsigned int, HashFunc, CmpFunc>& flow_sizes, 
                      size_t top_n = 10) {
        // Create vector of pairs for sorting
        std::vector<std::pair<const uint8_t*, unsigned int>> flows;
        flows.reserve(flow_sizes.size());
        
        for (const auto& [key, count] : flow_sizes) {
            flows.emplace_back(key, count);
        }
        
        // Sort by count in descending order
        std::partial_sort(flows.begin(), 
                         flows.begin() + std::min(top_n, flows.size()),
                         flows.end(),
                         [](const auto& a, const auto& b) { return a.second > b.second; });
        
        std::cout << "\nTop " << top_n << " flows:\n";
        std::cout << std::string(80, '-') << '\n';
        
        for (size_t i = 0; i < std::min(top_n, flows.size()); ++i) {
            printFlow(flows[i].first, flows[i].second);
        }
        std::cout << std::string(80, '-') << '\n';
    }

public:
    void run() {
        std::cout << "Preparing dataset\n";
        
        std::vector<uint8_t*> keys;
        keys.reserve(kMaxItems);
        
        std::unordered_map<uint8_t*, unsigned int, HashFunc, CmpFunc> flow_sizes;
        
        size_t item_count = readTraces("../data/", keys, flow_sizes);
        
        std::cout << "Items: " << item_count << ", Flows: " << flow_sizes.size() << '\n';
        printTopFlows(flow_sizes);
        std::cout << "*********************\n";

        std::cout << "Preparing algorithm\n";
        jigsaw::Sketch<jigsaw::IPv4Flow, 1024, 79, 8, 8> sketch;
        printMemoryInfo();

        std::cout << "Inserting items\n";
        auto start = clock();
        
        // Keep the hot path as simple as possible
        for (size_t i = 0; i < item_count; i++) {
            // Directly reinterpret bytes as IPv4Flow
            const jigsaw::IPv4Flow& flow = *reinterpret_cast<const jigsaw::IPv4Flow*>(keys[i]);
            sketch.insert(flow);
        }
        
        auto end = clock();
        double seconds = static_cast<double>(end - start) / CLOCKS_PER_SEC;
        double throughput = (item_count / 1e6) / seconds;
        
        std::cout << "Time: " << seconds << " seconds\n"
                 << "Throughput: " << throughput << " Mpps\n"
                 << "Per insert: " << 1000.0 / throughput << " ns\n"
                 << "*********************\n";

        // Cleanup
        for (auto key : keys) {
            free(key);
        }
    }

private:
    void printMemoryInfo() const {
        constexpr uint32_t BUCKET_NUM = 1024;
        constexpr uint32_t CELL_NUM_H = 8;
        constexpr uint32_t CELL_NUM_L = 8;
        constexpr uint32_t LEFT_PART_BITS = 79;
        
        double bucketMem = BUCKET_NUM * (CELL_NUM_H + CELL_NUM_L) * ((16+18)/8.0) / 1024.0;
        uint32_t auxiliaryListWordNum = int(ceil(BUCKET_NUM * CELL_NUM_H * 
            (LEFT_PART_BITS + jigsaw::Config::EXTRA_BITS_NUM) / 64.0));
        double auxiliaryListMem = auxiliaryListWordNum * 8 / 1024.0;

        std::cout << "bucketMem: " << bucketMem << "KB\n"
                 << "auxiliaryListMem: " << auxiliaryListMem << "KB\n"
                 << "totalMem: " << bucketMem + auxiliaryListMem << "KB\n"
                 << "*********************\n";
    }
};

int main() {
    try {
        TraceProcessor processor;
        processor.run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
    return 0;
} 
