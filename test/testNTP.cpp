/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(NTPTest, Generic) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    uint unknown;
    getProtocols("./pcaps/ntp.pcap", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_NTP], (uint) 30);
}
