/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(BGPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/bgp.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_BGP], (uint) 13);
}
