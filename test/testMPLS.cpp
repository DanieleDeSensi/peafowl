/**
 *  Test for MPLS datalink protocol.
 **/
#include "common.h"

TEST(MPLS, Generic) {
    std::vector<uint> protocols;
    uint icmp_packets = 0;
    for(auto r : getProtocols("./pcaps/mpls_one.cap", protocols)){
      if(r.protocol_l4 == IPPROTO_ICMP){
        ++icmp_packets;
      }
    }
    EXPECT_EQ(icmp_packets, (uint) 5);

    icmp_packets = 0;
    for(auto r : getProtocols("./pcaps/mpls_two.pcap", protocols)){
      if(r.protocol_l4 == IPPROTO_ICMP){
        ++icmp_packets;
      }
    }
    EXPECT_EQ(icmp_packets, (uint) 5);
}
