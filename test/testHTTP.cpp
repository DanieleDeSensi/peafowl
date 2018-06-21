/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(HTTPTest, Generic) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    uint unknown;
    getProtocols("./pcaps/http.cap", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(tcpProtocols[DPI_PROTOCOL_TCP_HTTP], (uint) 35);
    getProtocols("./pcaps/skype-irc.cap", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(tcpProtocols[DPI_PROTOCOL_TCP_HTTP], (uint) 12);
}
