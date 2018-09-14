/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(BGPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/bgp.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_BGP], (uint) 13);
}
