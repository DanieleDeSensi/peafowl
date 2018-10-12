/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(DHCP6Test, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/dhcpv6_1.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_DHCPv6], (uint) 6);
    getProtocols("./pcaps/dhcpv6_2.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_DHCPv6], (uint) 6);
}
