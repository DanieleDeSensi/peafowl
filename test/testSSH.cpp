/**
 *  Test for SSH protocol.
 **/
#include "common.h"

TEST(SSHTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/ssh.cap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_SSH], (uint) 86);
}
