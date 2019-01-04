/**
 *  Test for MQTT protocol.
 **/
#include "common.h"

TEST(MQTTTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/mqtt-1.pcapng", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_MQTT], (uint) 19);
    getProtocols("./pcaps/mqtt-2.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_MQTT], (uint) 14);
}
