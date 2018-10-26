/**
 *  Test for SSDP protocol.
 **/
#include "common.h"

TEST(SSDPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/whatsapp.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_SSDP], (uint) 6);
    getProtocols("./pcaps/dropbox.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_SSDP], (uint) 140);
}
