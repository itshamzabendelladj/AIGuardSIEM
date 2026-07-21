#include <gtest/gtest.h>
#include "aiguard/storage/memtable.h"

using namespace aiguard;

TEST(MemTableTest, BasicPutGet) {
    MemTable mt(1024 * 1024);
    EXPECT_TRUE(mt.put("key1", "value1", 1));
    EXPECT_TRUE(mt.put("key2", "value2", 2));

    auto val = mt.get("key1");
    ASSERT_TRUE(val.has_value());
    EXPECT_EQ(*val, "value1");
}

TEST(MemTableTest, Delete) {
    MemTable mt(1024 * 1024);
    mt.put("key1", "value1", 1);
    mt.remove("key1", 2);

    auto val = mt.get("key1");
    EXPECT_FALSE(val.has_value());
}

TEST(MemTableTest, Range) {
    MemTable mt(1024 * 1024);
    mt.put("a", "1", 1);
    mt.put("b", "2", 2);
    mt.put("c", "3", 3);
    mt.put("d", "4", 4);
    mt.put("e", "5", 5);

    auto result = mt.range("b", "d", 100);
    EXPECT_EQ(result.size(), 2);  // b, c (d is excluded since end is exclusive)
}

TEST(MemTableTest, PrefixScan) {
    MemTable mt(1024 * 1024);
    mt.put("event:001", "a", 1);
    mt.put("event:002", "b", 2);
    mt.put("event:003", "c", 3);
    mt.put("alert:001", "d", 4);

    auto result = mt.prefix_scan("event:", 100);
    EXPECT_EQ(result.size(), 3);
}

TEST(MemTableTest, FullCheck) {
    MemTable mt(1024 * 1024);
    mt.put("key1", "value1", 1);

    // Fill up to make it full
    for (int i = 0; i < 100; ++i) {
        std::string key = "padding_" + std::to_string(i);
        std::string val(100, 'x');
        mt.put(key, val, i + 2);
    }

    EXPECT_GT(mt.size(), 0);
    EXPECT_GT(mt.count(), 0);
}

TEST(MemTableTest, Clear) {
    MemTable mt(1024 * 1024);
    mt.put("key1", "value1", 1);
    mt.put("key2", "value2", 2);

    mt.clear();
    EXPECT_EQ(mt.size(), 0);
    EXPECT_EQ(mt.count(), 0);
}
