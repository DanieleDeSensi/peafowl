/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(DHCPTest, DeprecatedCalls) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    getProtocolsOld("./pcaps/dhcp.pcap", tcpProtocols, udpProtocols);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_DHCP], (uint) 4);
    getProtocolsOld("./pcaps/sip-rtp.pcap", tcpProtocols, udpProtocols);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_DHCP], (uint) 2);
}

TEST(DHCPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/dhcp.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_DHCP], (uint) 4);
    getProtocols("./pcaps/sip-rtp.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_DHCP], (uint) 2);
}
