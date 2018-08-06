/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(BGPTest, DeprecatedCalls) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    getProtocolsOld("./pcaps/bgp.pcap", tcpProtocols, udpProtocols);
    EXPECT_EQ(tcpProtocols[DPI_PROTOCOL_TCP_BGP], (uint) 13);
}


TEST(BGPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/bgp.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_BGP], (uint) 13);
}
