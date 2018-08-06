/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(SIPTest, DeprecatedCalls) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    getProtocolsOld("./pcaps/sip-rtp.pcap", tcpProtocols, udpProtocols);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_SIP], (uint) 102);
}

TEST(SIPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/sip-rtp.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_SIP], (uint) 102);
}
