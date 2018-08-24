/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(NTPTest, DeprecatedCalls) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    getProtocolsOld("./pcaps/ntp.pcap", tcpProtocols, udpProtocols);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_NTP], (uint) 30);
}

TEST(NTPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/ntp.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_NTP], (uint) 30);
    getProtocols("./pcaps/whatsapp.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_NTP], (uint) 4);
}
