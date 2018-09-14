/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(SkypeTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/skype-irc.cap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_SKYPE], (uint) 326);
}
