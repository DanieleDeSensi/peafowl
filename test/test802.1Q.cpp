/**
 *  Test for 802.1Q datalink protocol.
 **/
#include "common.h"

TEST(eightzerotwoQ, Generic) {
    std::vector<uint> protocols;
    uint icmp_packets = 0;
    for(auto r : getProtocols("./pcaps/802.1Q_dvlan.cap", protocols)){
      if(r.protocol_l4 == IPPROTO_ICMP){
        ++icmp_packets;
      }
    }
    EXPECT_EQ(icmp_packets, (uint) 20);
}
