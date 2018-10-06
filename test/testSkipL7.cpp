/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

#define DUMMY_ID 100

TEST(SkipL7Test, Generic) {
    std::vector<pfwl_protocol_l7_t> identifiers = {DUMMY_ID, PFWL_PROTOCOL_BGP, PFWL_PROTOCOL_HTTP};

    for(pfwl_protocol_l7_t id : identifiers){
        size_t count = 0;
        std::vector<uint> protocols;
        pfwl_state_t* state = pfwl_init();
        EXPECT_EQ(pfwl_skip_L7_parsing_by_port(state, IPPROTO_TCP, 80, id) , 0);
        for(auto r : getProtocolsWithState("./pcaps/http.cap", protocols, state)){
            if(r.protocol_l4 == IPPROTO_TCP && r.protocol_l7 == id){
                ++count;
            }
        }
        pfwl_terminate(state);
        EXPECT_GE(count, (uint) 35);
    }
}
