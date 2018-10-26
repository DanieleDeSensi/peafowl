/**
 *  Test for Stratum protocol.
 **/
#include "common.h"

TEST(StratumTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/stratum.pcap", protocols);
    // Some packets in this pcap look like jsonrpc-stratum but they
    // are not, since they have an " id" field instead of an "id" field (extra whitespace not valid)
    EXPECT_EQ(protocols[PFWL_PROTO_L7_JSON_RPC], (uint) 269);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_STRATUM], (uint) 269);
}
