/**
 *  Test for MDNS protocol.
 **/
#include "common.h"

TEST(MDNSTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/dropbox.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_MDNS], (uint) 16);
}
