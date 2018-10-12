/**
 *  Test for 802.1Q datalink protocol.
 **/
#include "common.h"

TEST(eightzerotwoQ, Generic) {
    std::vector<uint> protocols;
    uint icmp_packets = 0;
    getProtocols("./pcaps/802.1Q_dvlan.cap", protocols, NULL, [&](pfwl_status_t status, pfwl_dissection_info_t r){
      if(r.l4.protocol == IPPROTO_ICMP){
        ++icmp_packets;
      }
    });
    EXPECT_EQ(icmp_packets, (uint) 20);
}
