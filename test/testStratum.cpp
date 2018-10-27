/**
 *  Test for Stratum protocol.
 **/
#include "common.h"

TEST(StratumTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/stratum.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_JSON_RPC], (uint) 313);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_STRATUM], (uint) 313);
}
