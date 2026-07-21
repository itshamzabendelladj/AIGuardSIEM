#include <gtest/gtest.h>
#include "aiguard/syslog/syslog_parser.h"
#include <string>

using namespace aiguard;

TEST(SyslogParserTest, ParseRFC5424Basic) {
    std::string msg = "<34>1 2024-01-15T10:30:00.123Z myhost myapp 1234 ID47 [exampleSDID@32473 iut=\"3\"] BAnAnA";
    auto result = SyslogParser::parse(msg);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->priority, 34);
    EXPECT_EQ(result->facility, SyslogFacility::Auth);
    EXPECT_EQ(result->severity, SyslogSeverity::Critical);
    EXPECT_EQ(result->version, 1);
    EXPECT_EQ(result->hostname, "myhost");
    EXPECT_EQ(result->app_name, "myapp");
    EXPECT_EQ(result->proc_id, "1234");
    EXPECT_EQ(result->msg_id, "ID47");
    EXPECT_EQ(result->message, "BAnAnA");
}

TEST(SyslogParserTest, ParseRFC3164Basic) {
    std::string msg = "<34>Jan 15 10:30:00 myhost myapp: Something happened";
    auto result = SyslogParser::parse(msg);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->priority, 34);
    EXPECT_EQ(result->facility, SyslogFacility::Auth);
    EXPECT_EQ(result->severity, SyslogSeverity::Critical);
    EXPECT_EQ(result->version, 0);
    EXPECT_EQ(result->hostname, "myhost");
    EXPECT_EQ(result->app_name, "myapp");
}

TEST(SyslogParserTest, ParseRFC3164WithPID) {
    std::string msg = "<133>Jan 15 10:30:00 myhost myapp[1234]: Test message";
    auto result = SyslogParser::parse(msg);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->app_name, "myapp");
    EXPECT_EQ(result->proc_id, "1234");
    EXPECT_EQ(result->message, "Test message");
}

TEST(SyslogParserTest, ParseEmptyMessage) {
    auto result = SyslogParser::parse("");
    EXPECT_FALSE(result.has_value());
}

TEST(SyslogParserTest, ParseInvalidPriority) {
    auto result = SyslogParser::parse("not a syslog message");
    EXPECT_FALSE(result.has_value());
}

TEST(SyslogParserTest, ParsePriorityRange) {
    for (int p = 0; p < 192; p += 8) {
        std::string msg = "<" + std::to_string(p) + ">1 2024-01-15T10:30:00Z host app - - - test";
        auto result = SyslogParser::parse(msg);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->priority, p);
        EXPECT_EQ(static_cast<int>(result->facility), p / 8);
        EXPECT_EQ(static_cast<int>(result->severity), 0);
    }
}

TEST(SyslogParserTest, FacilityToString) {
    EXPECT_EQ(SyslogParser::facility_to_string(SyslogFacility::Kernel), "kernel");
    EXPECT_EQ(SyslogParser::facility_to_string(SyslogFacility::Mail), "mail");
    EXPECT_EQ(SyslogParser::facility_to_string(SyslogFacility::Local0), "local0");
    EXPECT_EQ(SyslogParser::facility_to_string(SyslogFacility::Local7), "local7");
}

TEST(SyslogParserTest, SeverityToString) {
    EXPECT_EQ(SyslogParser::severity_to_string(SyslogSeverity::Emergency), "emergency");
    EXPECT_EQ(SyslogParser::severity_to_string(SyslogSeverity::Critical), "critical");
    EXPECT_EQ(SyslogParser::severity_to_string(SyslogSeverity::Informational), "informational");
    EXPECT_EQ(SyslogParser::severity_to_string(SyslogSeverity::Debug), "debug");
}

TEST(SyslogParserTest, MapSeverity) {
    EXPECT_EQ(SyslogParser::map_severity(SyslogSeverity::Emergency), Severity::Critical);
    EXPECT_EQ(SyslogParser::map_severity(SyslogSeverity::Critical), Severity::Critical);
    EXPECT_EQ(SyslogParser::map_severity(SyslogSeverity::Error), Severity::High);
    EXPECT_EQ(SyslogParser::map_severity(SyslogSeverity::Warning), Severity::Medium);
    EXPECT_EQ(SyslogParser::map_severity(SyslogSeverity::Informational), Severity::Info);
}

TEST(SyslogParserTest, ParseStructuredData) {
    std::string sd = "[exampleSDID@32473 iut=\"3\" eventSource=\"App\"]";
    auto result = SyslogParser::parse_structured_data(sd);
    EXPECT_EQ(result.size(), 2);
    EXPECT_EQ(result["exampleSDID@32473.iut"], "3");
    EXPECT_EQ(result["exampleSDID@32473.eventSource"], "App");
}

TEST(SyslogParserTest, ParseRFC5424NoStructuredData) {
    std::string msg = "<165>1 2024-01-15T10:30:00Z host app - - - Hello World";
    auto result = SyslogParser::parse(msg);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->hostname, "host");
    EXPECT_EQ(result->app_name, "app");
    EXPECT_EQ(result->message, "Hello World");
    EXPECT_TRUE(result->structured_data.empty());
}

TEST(SyslogParserTest, ParseRFC5424NilValues) {
    std::string msg = "<165>1 2024-01-15T10:30:00Z - - - - - Test";
    auto result = SyslogParser::parse(msg);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->hostname, "-");
    EXPECT_EQ(result->app_name, "-");
    EXPECT_EQ(result->message, "Test");
}
