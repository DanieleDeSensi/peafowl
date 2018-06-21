/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(DHCP6Test, Generic) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    uint unknown;
    getProtocols("./pcaps/dhcpv6_1.pcap", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_DHCPv6], (uint) 6);
    getProtocols("./pcaps/dhcpv6_2.pcap", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_DHCPv6], (uint) 6);
}
