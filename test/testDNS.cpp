/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(DNSTest, Generic) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    uint unknown;
    getProtocols("./pcaps/http.cap", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_DNS], (uint) 2);
    getProtocols("./pcaps/smtp.pcap", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_DNS], (uint) 2);
    getProtocols("./pcaps/ntp.pcap", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_DNS], (uint) 2);
    getProtocols("./pcaps/sip-rtp.pcap", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_DNS], (uint) 357);
    getProtocols("./pcaps/skype-irc.cap", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_DNS], (uint) 707);
}
