/**
 *  Test for Monero protocol.
 **/
#include "common.h"

TEST(MoneroTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/monero.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_JSON_RPC], (uint) 313);
    EXPECT_TRUE(protocols[PFWL_PROTO_L7_MONERO] == (uint) 313 ||
                protocols[PFWL_PROTO_L7_ZCASH] == (uint) 313);
}
