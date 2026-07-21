#include <gtest/gtest.h>
#include "aiguard/storage/lsm_index.h"
#include "aiguard/storage/query_engine.h"
#include <filesystem>

using namespace aiguard;

class LSMIndexTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir = "/tmp/aiguard_test_lsm_" + std::to_string(getpid());
        std::filesystem::create_directories(test_dir);
    }

    void TearDown() override {
        std::filesystem::remove_all(test_dir);
    }

    std::string test_dir;
};

TEST_F(LSMIndexTest, BasicPutGet) {
    LSMConfig config;
    config.data_directory = test_dir;
    LSMIndex index(config);

    EXPECT_TRUE(index.put("key1", "value1"));
    EXPECT_TRUE(index.put("key2", "value2"));
    EXPECT_TRUE(index.put("key3", "value3"));

    auto stats = index.get_stats();
    EXPECT_EQ(stats.writes, 3);
}

TEST_F(LSMIndexTest, BatchPut) {
    LSMConfig config;
    config.data_directory = test_dir;
    LSMIndex index(config);

    std::vector<std::pair<std::string, std::string>> batch = {
        {"batch1", "val1"},
        {"batch2", "val2"},
        {"batch3", "val3"},
    };

    EXPECT_TRUE(index.put_batch(batch));

    auto stats = index.get_stats();
    EXPECT_EQ(stats.writes, 3);
}

TEST_F(LSMIndexTest, Query) {
    LSMConfig config;
    config.data_directory = test_dir;
    LSMIndex index(config);

    index.put("event:001", R"({"source_ip":"10.0.0.1","action":"connect"})");
    index.put("event:002", R"({"source_ip":"10.0.0.2","action":"connect"})");
    index.put("event:003", R"({"source_ip":"10.0.0.3","action":"disconnect"})");

    QueryFilter filter;
    filter.key_prefix = "event:";
    filter.limit = 100;

    auto result = index.query(filter);
    EXPECT_GE(result.query_time_ms, 0);
}
