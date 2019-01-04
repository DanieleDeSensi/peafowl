/**
 *  Test for STUN protocol.
 **/
#include "common.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

TEST(STUNTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/stun-0.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_STUN], (uint) 108);
}


TEST(STUNTest, AddressPort) {
    std::vector<uint> protocols;
    pfwl_state_t* state = pfwl_init();
    pfwl_field_add_L7(state, PFWL_FIELDS_L7_STUN_MAPPED_ADDRESS);
    pfwl_field_add_L7(state, PFWL_FIELDS_L7_STUN_MAPPED_ADDRESS_PORT);
    int addressesFound = 0;
    pfwl_string_t address;
    int64_t port = 0;
    getProtocols("./pcaps/stun-0.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
        if(r.l7.protocol == PFWL_PROTO_L7_STUN){
            if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_STUN_MAPPED_ADDRESS, &address)){
              pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_STUN_MAPPED_ADDRESS_PORT, &port);
              if(addressesFound == 0){
                EXPECT_STREQ((const char*) address.value, "70.199.128.46");
                EXPECT_EQ((uint32_t) port, 4604);
              }else if(addressesFound == 3){
                EXPECT_STREQ((const char*) address.value, "70.199.128.46");
                EXPECT_EQ((uint32_t) port, 4587);
              }
              ++addressesFound;
            }
        }
    });
    EXPECT_TRUE(47);
}
