/**
 *  Test for MQTT protocol.
 **/
#include "common.h"

TEST(MQTTTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/mqtt-1.pcapng", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_MQTT], (uint) 14);
    getProtocols("./pcaps/mqtt-2.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_MQTT], (uint) 14);
}

TEST(MQTTTest, GenericNoReord) {
    std::vector<uint> protocols;
    
    pfwl_state_t* state = pfwl_init();    
    pfwl_tcp_reordering_disable(state);
    getProtocols("./pcaps/mqtt-1.pcapng", protocols, state);
    pfwl_terminate(state);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_MQTT], (uint) 19);
    
    state = pfwl_init();    
    pfwl_tcp_reordering_disable(state);
    getProtocols("./pcaps/mqtt-2.pcap", protocols, state);
    pfwl_terminate(state);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_MQTT], (uint) 19);
}
