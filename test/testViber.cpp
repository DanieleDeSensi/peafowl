/**
 *  Test for Viber protocol.
 **/
#include "common.h"

TEST(ViberTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/viber.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_VIBER], (uint) 93);
}
