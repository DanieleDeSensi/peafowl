/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(HTTPTest, DeprecatedCalls) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    getProtocolsOld("./pcaps/http.cap", tcpProtocols, udpProtocols);
    EXPECT_EQ(tcpProtocols[DPI_PROTOCOL_TCP_HTTP], (uint) 35);
    getProtocolsOld("./pcaps/skype-irc.cap", tcpProtocols, udpProtocols);
    EXPECT_EQ(tcpProtocols[DPI_PROTOCOL_TCP_HTTP], (uint) 12);
}

TEST(HTTPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/http.cap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_HTTP], (uint) 35);
    getProtocols("./pcaps/skype-irc.cap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_HTTP], (uint) 12);
    getProtocols("./pcaps/whatsapp.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_HTTP], (uint) 4);
    getProtocols("./pcaps/6in4tunnel.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_HTTP], (uint) 6);
    getProtocols("./pcaps/dropbox.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_HTTP], (uint) 11);
    getProtocols("./pcaps/spotify.pcapng", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_HTTP], (uint) 10);
}
