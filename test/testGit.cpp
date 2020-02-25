/**
 *  Test for Git protocol.
 **/
#include "common.h"

TEST(DropboxTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/git.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_GIT], (uint) 87);
}
