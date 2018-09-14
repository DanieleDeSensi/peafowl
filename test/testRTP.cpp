/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(RTPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/sip-rtp.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_RTP], (uint) 9);
}
