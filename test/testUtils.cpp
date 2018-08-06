/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(UtilsTest, ProtoToFromString) {
    EXPECT_STREQ(dpi_proto_to_string(DPI_PROTOCOL_DHCP), "DHCP");
    EXPECT_STREQ(dpi_proto_to_string(DPI_PROTOCOL_HTTP), "HTTP");
    EXPECT_EQ(dpi_proto_to_string(DPI_NUM_PROTOCOLS), reinterpret_cast<const char*>(NULL));

    EXPECT_EQ(dpi_string_to_proto("SMTP"), DPI_PROTOCOL_SMTP);
    EXPECT_EQ(dpi_string_to_proto("SIP"), DPI_PROTOCOL_SIP);
    EXPECT_EQ(dpi_string_to_proto("WRONGSTRING"), DPI_NUM_PROTOCOLS);

    dpi_protocol_t pp;
    pp.l4prot = IPPROTO_TCP;
    pp.l7prot = DPI_PROTOCOL_TCP_HTTP;
    EXPECT_EQ(dpi_old_protocols_to_new(pp), DPI_PROTOCOL_HTTP);
    EXPECT_EQ(dpi_new_protocols_to_old(DPI_PROTOCOL_DNS), DPI_PROTOCOL_UDP_DNS);

    const char** protocols_names = dpi_get_protocols_names();
    for(size_t i = 0; i < DPI_NUM_PROTOCOLS; i++){
        EXPECT_STREQ(protocols_names[i], dpi_proto_to_string((dpi_l7_prot_id)i));
    }
    EXPECT_STREQ("HTTP", protocols_names[(size_t) DPI_PROTOCOL_HTTP]);
    EXPECT_STREQ("DHCP", protocols_names[(size_t) DPI_PROTOCOL_DHCP]);
}
