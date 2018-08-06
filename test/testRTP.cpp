/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(RTPTest, DeprecatedCalls) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    getProtocolsOld("./pcaps/sip-rtp.pcap", tcpProtocols, udpProtocols);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_RTP], (uint) 9);
}

TEST(RTPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/sip-rtp.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_RTP], (uint) 9);
}
