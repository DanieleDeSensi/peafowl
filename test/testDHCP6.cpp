/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(DHCP6Test, DeprecatedCalls) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    getProtocolsOld("./pcaps/dhcpv6_1.pcap", tcpProtocols, udpProtocols);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_DHCPv6], (uint) 6);
    getProtocolsOld("./pcaps/dhcpv6_2.pcap", tcpProtocols, udpProtocols);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_DHCPv6], (uint) 6);
}


TEST(DHCP6Test, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/dhcpv6_1.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_DHCPv6], (uint) 6);
    getProtocols("./pcaps/dhcpv6_2.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_DHCPv6], (uint) 6);
}
