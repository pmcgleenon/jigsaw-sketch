#include <gtest/gtest.h>
#include <jigsaw/sketch.hpp>


class SketchIPv4Test : public ::testing::Test {
protected:
    static constexpr uint32_t BUCKET_NUM = 1024;
    static constexpr uint32_t LEFT_PART_BITS = 104;
    static constexpr uint32_t CELL_NUM_H = 8;
    static constexpr uint32_t CELL_NUM_L = 8;
    
    jigsaw::Sketch<jigsaw::IPv4Flow, BUCKET_NUM, LEFT_PART_BITS, CELL_NUM_H, CELL_NUM_L> sketch;
};

TEST_F(SketchIPv4Test, BasicInsertion) {
    jigsaw::IPv4Flow flow{};
    flow.src_ip = 0x12345678;
    flow.dst_ip = 0x87654321;
    flow.src_port = 80;
    flow.dst_port = 443;
    flow.protocol = 6;  // TCP

    // Should not throw
    EXPECT_NO_THROW(sketch.insert(flow));
}

TEST_F(SketchIPv4Test, QueryAfterInsertion) {
    jigsaw::IPv4Flow flow{};
    flow.src_ip = 0x12345678;
    flow.dst_ip = 0x87654321;
    flow.src_port = 80;
    flow.dst_port = 443;
    flow.protocol = 6;  // TCP

    // Insert multiple times to ensure it's counted
    for (int i = 0; i < 100; i++) {
        sketch.insert(flow);
    }

    // Query should return non-zero count
    uint32_t count = sketch.query(flow);
    EXPECT_GT(count, 0);
}


class SketchIPv6Test : public ::testing::Test {
protected:
    static constexpr uint32_t BUCKET_NUM = 1024;
    static constexpr uint32_t LEFT_PART_BITS = 104;
    static constexpr uint32_t CELL_NUM_H = 8;
    static constexpr uint32_t CELL_NUM_L = 8;
    
    jigsaw::Sketch<jigsaw::IPv6Flow, BUCKET_NUM, LEFT_PART_BITS, CELL_NUM_H, CELL_NUM_L> sketch;
};

TEST_F(SketchIPv6Test, BasicInsertion) {
    jigsaw::IPv6Flow flow{};
    
    // Set IPv6 addresses as bytes (2001:0db8::1)
    uint8_t src_ip[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    // 2001:0db8::2
    uint8_t dst_ip[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
                         
    std::memcpy(flow.src_ip, src_ip, 16);
    std::memcpy(flow.dst_ip, dst_ip, 16);
    flow.src_port = 80;
    flow.dst_port = 443;
    flow.protocol = 6;  // TCP

    EXPECT_NO_THROW(sketch.insert(flow));
}

TEST_F(SketchIPv6Test, QueryAfterInsertion) {
    jigsaw::IPv6Flow flow{};
    
    // Set IPv6 addresses as bytes (2001:0db8::1)
    uint8_t src_ip[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    // 2001:0db8::2
    uint8_t dst_ip[16] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
                         
    std::memcpy(flow.src_ip, src_ip, 16);
    std::memcpy(flow.dst_ip, dst_ip, 16);
    flow.src_port = 80;
    flow.dst_port = 443;
    flow.protocol = 6;  // TCP

    for (int i = 0; i < 100; i++) {
        sketch.insert(flow);
    }

    uint32_t count = sketch.query(flow);
    EXPECT_GT(count, 0);
}


class SketchCompactStringTest : public ::testing::Test {
protected:
    static constexpr uint32_t BUCKET_NUM = 1024;
    static constexpr uint32_t LEFT_PART_BITS = 104;
    static constexpr uint32_t CELL_NUM_H = 8;
    static constexpr uint32_t CELL_NUM_L = 8;
    
    jigsaw::Sketch<jigsaw::CompactStringKey, BUCKET_NUM, LEFT_PART_BITS, CELL_NUM_H, CELL_NUM_L> sketch;
};

TEST_F(SketchCompactStringTest, BasicInsertion) {
    // Use the constructor with string_view
    jigsaw::CompactStringKey key("testkey");
    
    EXPECT_NO_THROW(sketch.insert(key));
}

TEST_F(SketchCompactStringTest, QueryAfterInsertion) {
    jigsaw::CompactStringKey key("anotherkey");
    
    for (int i = 0; i < 100; i++) {
        sketch.insert(key);
    }

    uint32_t count = sketch.query(key);
    EXPECT_GT(count, 0);
}
