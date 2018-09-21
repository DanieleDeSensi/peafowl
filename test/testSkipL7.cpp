/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

#define DUMMY_ID 100

TEST(SkipL7Test, Generic) {
    std::vector<pfwl_protocol_l7> identifiers = {DUMMY_ID, PFWL_PROTOCOL_BGP, PFWL_PROTOCOL_HTTP};

    for(pfwl_protocol_l7 id : identifiers){
        size_t count = 0;
        Pcap pcap("./pcaps/http.cap");
        pfwl_identification_result_t r;
        std::pair<const u_char*, unsigned long> pkt;
        pfwl_library_state_t* state = pfwl_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS);
        EXPECT_EQ(pfwl_skip_L7_parsing_by_port(state, IPPROTO_TCP, 80, id) , PFWL_STATE_UPDATE_SUCCESS);

        while((pkt = pcap.getNextPacket()).first != NULL){
            r = pfwl_get_protocol(state, pkt.first, pkt.second, time(NULL));
            if(r.protocol_l4 == IPPROTO_TCP &&
               r.protocol_l7 == id){
                ++count;
            }
        }

        pfwl_terminate(state);
        EXPECT_GE(count, (uint) 35);
    }
}
