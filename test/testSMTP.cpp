/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(SMTPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/smtp.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_SMTP], (uint) 47);
}
