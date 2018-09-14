/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(DHCPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/dhcp.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_DHCP], (uint) 4);
    getProtocols("./pcaps/sip-rtp.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_DHCP], (uint) 2);
}
