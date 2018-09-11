/**
 *  Test for SSH protocol.
 **/
#include "common.h"

TEST(SSHTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/ssh.cap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_SSH], (uint) 76);
}
