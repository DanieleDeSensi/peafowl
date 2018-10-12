/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(NTPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/ntp.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_NTP], (uint) 30);
    getProtocols("./pcaps/whatsapp.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_NTP], (uint) 4);
}
