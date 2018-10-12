/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(SkypeTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/skype-irc.cap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_SKYPE], (uint) 326);
}
