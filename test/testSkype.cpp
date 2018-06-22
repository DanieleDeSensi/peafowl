/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(SkypeTest, Generic) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    uint unknown;
    getProtocols("./pcaps/skype-irc.cap", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(udpProtocols[DPI_PROTOCOL_UDP_SKYPE], (uint) 326);
}
