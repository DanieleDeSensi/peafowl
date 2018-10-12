/**
 *  Test for MPLS datalink protocol.
 **/
#include "common.h"

TEST(MPLS, Generic) {
    std::vector<uint> protocols;
    uint icmp_packets = 0;
    getProtocols("./pcaps/mpls_one.cap", protocols, NULL, [&](pfwl_status_t status, pfwl_dissection_info_t r){
      if(r.l4.protocol == IPPROTO_ICMP){
        ++icmp_packets;
      }
    });
    EXPECT_EQ(icmp_packets, (uint) 5);

    icmp_packets = 0;
    getProtocols("./pcaps/mpls_two.pcap", protocols, NULL, [&](pfwl_status_t status, pfwl_dissection_info_t r){
      if(r.l4.protocol == IPPROTO_ICMP){
        ++icmp_packets;
      }
    });
    EXPECT_EQ(icmp_packets, (uint) 5);
}
