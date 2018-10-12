/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(UtilsTest, ProtoToFromString) {
    EXPECT_STREQ(pfwl_get_L7_protocol_name(PFWL_PROTO_L7_DHCP), "DHCP");
    EXPECT_STREQ(pfwl_get_L7_protocol_name(PFWL_PROTO_L7_HTTP), "HTTP");
    EXPECT_STREQ(pfwl_get_L7_protocol_name(PFWL_PROTO_L7_NUM), "Unknown");

    EXPECT_EQ(pfwl_get_L7_protocol_id("SMTP"), PFWL_PROTO_L7_SMTP);
    EXPECT_EQ(pfwl_get_L7_protocol_id("SIP"), PFWL_PROTO_L7_SIP);
    EXPECT_EQ(pfwl_get_L7_protocol_id("WRONGSTRING"), PFWL_PROTO_L7_NUM);

    const char** protocols_names = pfwl_get_L7_protocols_names();
    for(size_t i = 0; i < PFWL_PROTO_L7_NUM; i++){
        EXPECT_STREQ(protocols_names[i], pfwl_get_L7_protocol_name((pfwl_protocol_l7_t)i));
    }
    EXPECT_STREQ("HTTP", protocols_names[(size_t) PFWL_PROTO_L7_HTTP]);
    EXPECT_STREQ("DHCP", protocols_names[(size_t) PFWL_PROTO_L7_DHCP]);
}
