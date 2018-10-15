/**
 *  Test for Monero protocol.
 **/
#include "common.h"

TEST(MoneroTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/monero.pcap", protocols);
    EXPECT_TRUE(protocols[PFWL_PROTO_L7_MONERO] == (uint) 313 ||
                protocols[PFWL_PROTO_L7_ZCASH] == (uint) 313);
}
