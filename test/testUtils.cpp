/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(UtilsTest, ProtoToFromString) {
    EXPECT_STREQ(dpi_get_protocol_string(DPI_PROTOCOL_DHCP), "DHCP");
    EXPECT_STREQ(dpi_get_protocol_string(DPI_PROTOCOL_HTTP), "HTTP");
    EXPECT_STREQ(dpi_get_protocol_string(DPI_NUM_PROTOCOLS), "Unknown");

    EXPECT_EQ(dpi_get_protocol_id("SMTP"), DPI_PROTOCOL_SMTP);
    EXPECT_EQ(dpi_get_protocol_id("SIP"), DPI_PROTOCOL_SIP);
    EXPECT_EQ(dpi_get_protocol_id("WRONGSTRING"), DPI_NUM_PROTOCOLS);

    const char** protocols_names = dpi_get_protocols_strings();
    for(size_t i = 0; i < DPI_NUM_PROTOCOLS; i++){
        EXPECT_STREQ(protocols_names[i], dpi_get_protocol_string((pfwl_protocol_l7)i));
    }
    EXPECT_STREQ("HTTP", protocols_names[(size_t) DPI_PROTOCOL_HTTP]);
    EXPECT_STREQ("DHCP", protocols_names[(size_t) DPI_PROTOCOL_DHCP]);
}
