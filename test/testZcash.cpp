/**
 *  Test for Zcash protocol.
 **/
#include "common.h"

TEST(ZcashTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/zcash.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_ZCASH], (uint) 142);
}
