/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(UtilsTest, ProtoToFromString) {
    EXPECT_STREQ(pfwl_get_protocol_string(PFWL_PROTOCOL_DHCP), "DHCP");
    EXPECT_STREQ(pfwl_get_protocol_string(PFWL_PROTOCOL_HTTP), "HTTP");
    EXPECT_STREQ(pfwl_get_protocol_string(PFWL_NUM_PROTOCOLS), "Unknown");

    EXPECT_EQ(pfwl_get_protocol_id("SMTP"), PFWL_PROTOCOL_SMTP);
    EXPECT_EQ(pfwl_get_protocol_id("SIP"), PFWL_PROTOCOL_SIP);
    EXPECT_EQ(pfwl_get_protocol_id("WRONGSTRING"), PFWL_NUM_PROTOCOLS);

    const char** protocols_names = pfwl_get_protocols_strings();
    for(size_t i = 0; i < PFWL_NUM_PROTOCOLS; i++){
        EXPECT_STREQ(protocols_names[i], pfwl_get_protocol_string((pfwl_protocol_l7)i));
    }
    EXPECT_STREQ("HTTP", protocols_names[(size_t) PFWL_PROTOCOL_HTTP]);
    EXPECT_STREQ("DHCP", protocols_names[(size_t) PFWL_PROTOCOL_DHCP]);
}
