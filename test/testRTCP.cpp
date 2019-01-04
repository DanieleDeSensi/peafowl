/**
 *  Test for RTCP protocol.
 **/
#include "common.h"

TEST(RTCPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/sip-rtp.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_RTCP], (uint) 1);
}


static void testFields(pfwl_state_t* state){
    std::vector<uint> protocols;
    int64_t pkts = 0, octects = 0;
    getProtocols("./pcaps/sip-rtp.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
        if(r.l7.protocol == PFWL_PROTO_L7_RTCP){
            pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_SENDER_PKT_COUNT, &pkts);
            pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_SENDER_OCT_COUNT, &octects);
        }
    });
    EXPECT_EQ(((uint32_t) pkts), 9);
    EXPECT_EQ(((uint32_t) octects), 1548);
}

TEST(RTCPTest, Fields) {
    pfwl_state_t* state = pfwl_init();
    pfwl_field_add_L7(state, PFWL_FIELDS_L7_RTCP_SENDER_PKT_COUNT);
    pfwl_field_add_L7(state, PFWL_FIELDS_L7_RTCP_SENDER_OCT_COUNT);
    testFields(state);
}

TEST(RTCPTest, FieldsAll) {
    pfwl_state_t* state = pfwl_init();
    pfwl_field_add_L7(state, PFWL_FIELDS_L7_RTCP_SENDER_ALL);
    testFields(state);
}