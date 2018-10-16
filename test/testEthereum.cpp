/**
 *  Test for Ethereum protocol.
 **/
#include "common.h"

TEST(EthereumTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/ethereum.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_ETHEREUM], (uint) 813);
}
