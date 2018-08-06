/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(SMTPTest, DeprecatedCalls) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    getProtocolsOld("./pcaps/smtp.pcap", tcpProtocols, udpProtocols);
    EXPECT_EQ(tcpProtocols[DPI_PROTOCOL_TCP_SMTP], (uint) 47);
}

TEST(SMTPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/smtp.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_SMTP], (uint) 47);
}
