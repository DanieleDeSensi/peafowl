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
}
