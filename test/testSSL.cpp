/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(SSLTest, Generic) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    uint unknown;
    getProtocols("./pcaps/ssl.pcapng", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(tcpProtocols[DPI_PROTOCOL_TCP_SSL], (uint) 840);
}
