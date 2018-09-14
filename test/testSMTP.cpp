/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(SMTPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/smtp.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_SMTP], (uint) 47);
}
