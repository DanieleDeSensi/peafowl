/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(UtilsTest, ProtoToFromString) {
    dpi_protocol_t p;
    p.l4prot = IPPROTO_UDP;
    p.l7prot = DPI_PROTOCOL_UDP_DHCP;
    EXPECT_STREQ(protoToString(p), "DHCP");

    p.l4prot = IPPROTO_TCP;
    p.l7prot = DPI_PROTOCOL_TCP_HTTP;
    EXPECT_STREQ(protoToString(p), "HTTP");

    p.l4prot = IPPROTO_TCP;
    p.l7prot = DPI_NUM_TCP_PROTOCOLS;
    EXPECT_EQ(protoToString(p), reinterpret_cast<const char*>(NULL));


    p = stringToProto("SMTP");
    EXPECT_EQ(p.l4prot, IPPROTO_TCP);
    EXPECT_EQ(p.l7prot, DPI_PROTOCOL_TCP_SMTP);

    p = stringToProto("SIP");
    EXPECT_EQ(p.l4prot, IPPROTO_UDP);
    EXPECT_EQ(p.l7prot, DPI_PROTOCOL_UDP_SIP);

    p = stringToProto("WRONGSTRING");
    EXPECT_EQ(p.l4prot, (u_int8_t) -1);
    EXPECT_EQ(p.l7prot, (dpi_l7_prot_id) -1);
}
