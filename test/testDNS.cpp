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
}
