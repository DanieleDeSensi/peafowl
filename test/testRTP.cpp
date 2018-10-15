/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(RTPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/sip-rtp.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_RTP], (uint) 9);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_RTCP], (uint) 1);
}
