/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(RTPTest, Generic) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    uint unknown;
    getProtocols("./pcaps/sip-rtp.pcap", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_RTP], (uint) 9);
}
