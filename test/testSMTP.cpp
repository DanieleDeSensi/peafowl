/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(HTTPTest, Generic) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    uint unknown;
    getProtocols("./pcaps/smtp.pcap", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(tcpProtocols[DPI_PROTOCOL_TCP_SMTP], (uint) 47);
}
