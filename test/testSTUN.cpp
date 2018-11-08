/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(DNSTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/stun-0.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_STUN], (uint) 108);
}
