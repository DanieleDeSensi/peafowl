/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(DHCPTest, Generic) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    uint unknown;
    getProtocols("./pcaps/dhcp.pcap", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_DHCP], (uint) 4);
    getProtocols("./pcaps/sip-rtp.pcap", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_DHCP], (uint) 2);
}
