/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

#define DUMMY_ID 100

TEST(SkipL7Test, Generic) {
    std::vector<dpi_l7_prot_id> identifiers = {DUMMY_ID, DPI_PROTOCOL_BGP, DPI_PROTOCOL_HTTP};


    for(dpi_l7_prot_id id : identifiers){
        size_t count = 0;
        Pcap pcap("./pcaps/http.cap");
        dpi_identification_result_t r;
        std::pair<const u_char*, unsigned long> pkt;
        dpi_library_state_t* state = dpi_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS);
        EXPECT_EQ(dpi_skip_L7_parsing_by_port(state, IPPROTO_TCP, 80, id) , DPI_STATE_UPDATE_SUCCESS);

        while((pkt = pcap.getNextPacket()).first != NULL){
            r = dpi_get_protocol(state, pkt.first, pkt.second, time(NULL));
            if(r.protocol.l4prot == IPPROTO_TCP &&
               r.protocol.l7prot == id){
                ++count;
            }
        }

        dpi_terminate(state);
        EXPECT_GE(count, (uint) 35);
    }
}
