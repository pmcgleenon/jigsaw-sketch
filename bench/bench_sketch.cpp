#include <benchmark/benchmark.h>
#include <jigsaw/sketch.hpp>
#include <vector>
#include <random>

// Helper function to generate random flows without storing them all in memory
class FlowGenerator {
private:
    std::mt19937 gen;
    std::uniform_int_distribution<uint32_t> ip_dist;
    std::uniform_int_distribution<uint16_t> port_dist;
    std::uniform_int_distribution<uint8_t> proto_dist;

public:
    FlowGenerator(uint32_t seed = 42) : 
        gen(seed),
        ip_dist(1, 0xFFFFFFFF),
        port_dist(1, 65535),
        proto_dist(1, 255) {}

    // Generate next random flow without reseeding
    jigsaw::IPv4Flow next() {
        return {
            .src_ip = ip_dist(gen),
            .dst_ip = ip_dist(gen),
            .src_port = port_dist(gen),
            .dst_port = port_dist(gen),
            .protocol = static_cast<uint8_t>(proto_dist(gen))
        };
    }
};

static void BM_SketchInsertion(benchmark::State& state) {
    jigsaw::Sketch<jigsaw::IPv4Flow, 1024, 26, 8, 8> sketch;
    
    // Pre-generate flows before benchmarking to eliminate generation overhead
    constexpr size_t flow_count = 100000;
    std::vector<jigsaw::IPv4Flow> flows;
    flows.reserve(flow_count);
    
    FlowGenerator generator(42);
    for (size_t i = 0; i < flow_count; ++i) {
        flows.push_back(generator.next());
    }
    
    size_t index = 0;
    for (auto _ : state) {
        sketch.insert(flows[index % flow_count]);
        benchmark::DoNotOptimize(sketch);
        ++index;
    }
}
BENCHMARK(BM_SketchInsertion);

static void BM_SketchQuery(benchmark::State& state) {
    jigsaw::Sketch<jigsaw::IPv4Flow, 1024, 26, 8, 8> sketch;
    
    // Pre-populate with flows
    constexpr size_t preinsert_count = 1000000;
    FlowGenerator insert_gen(42);
    
    for (size_t i = 0; i < preinsert_count; ++i) {
        sketch.insert(insert_gen.next());
    }
    
    // Create a mix of existing and new flows to query
    std::vector<jigsaw::IPv4Flow> query_flows;
    query_flows.reserve(10000);  // Cache a reasonable number of flows
    
    // Add existing flows (from same generator with reset)
    FlowGenerator existing_gen(42);
    for (size_t i = 0; i < 5000; ++i) {
        query_flows.push_back(existing_gen.next());
    }
    
    // Add new flows
    FlowGenerator new_gen(43);
    for (size_t i = 0; i < 5000; ++i) {
        query_flows.push_back(new_gen.next());
    }
    
    size_t index = 0;
    for (auto _ : state) {
        auto count = sketch.query(query_flows[index % query_flows.size()]);
        benchmark::DoNotOptimize(count);
        ++index;
    }
}
BENCHMARK(BM_SketchQuery);

// Add a more focused benchmark just for the core insertion operation
static void BM_SketchInsertionCore(benchmark::State& state) {
    jigsaw::Sketch<jigsaw::IPv4Flow, 1024, 26, 8, 8> sketch;
    
    // Use a small set of pre-generated flows for maximum cache efficiency
    constexpr size_t flow_count = 64; // Small enough to fit in L1 cache
    std::vector<jigsaw::IPv4Flow> flows;
    flows.reserve(flow_count);
    
    FlowGenerator generator(42);
    for (size_t i = 0; i < flow_count; ++i) {
        flows.push_back(generator.next());
    }
    
    size_t index = 0;
    for (auto _ : state) {
        sketch.insert(flows[index & (flow_count-1)]); // Faster masking instead of modulo
        benchmark::DoNotOptimize(sketch);
        ++index;
    }
}
BENCHMARK(BM_SketchInsertionCore);

BENCHMARK_MAIN(); 