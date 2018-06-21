/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(BGPTest, Generic) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    uint unknown;
    getProtocols("./pcaps/bgp.pcap", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(tcpProtocols[DPI_PROTOCOL_TCP_BGP], (uint) 13);
}
