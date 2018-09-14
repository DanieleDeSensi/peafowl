/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

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
