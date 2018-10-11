/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

#define DUMMY_ID 100

TEST(SkipL7Test, Generic) {
    std::vector<pfwl_protocol_l7_t> identifiers = {(pfwl_protocol_l7_t)DUMMY_ID, PFWL_PROTOCOL_BGP, PFWL_PROTOCOL_HTTP};

    for(pfwl_protocol_l7_t id : identifiers){
        size_t count = 0;
        std::vector<uint> protocols;
        pfwl_state_t* state = pfwl_init();
        EXPECT_EQ(pfwl_skip_L7_parsing_by_port(state, IPPROTO_TCP, 80, id) , 0);
        getProtocols("./pcaps/http.cap", protocols, state, [&](pfwl_dissection_info_t r){
            if(r.l4.protocol == IPPROTO_TCP && r.l7.protocol == id){
                ++count;
            }
        });
        pfwl_terminate(state);
        EXPECT_GE(count, (uint) 35);
    }
}
