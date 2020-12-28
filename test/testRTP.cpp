/**
 *  Test for RTP protocol.
 **/
#include "common.h"

TEST(RTPTest, GenericOld) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/sip-rtp.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_RTP], (uint) 9);
}

TEST(RTPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/rtp.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_RTP], (uint) 15);
}
