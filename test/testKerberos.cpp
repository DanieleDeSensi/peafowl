/**
 *  Test for Kerberos protocol.
 **/
#include "common.h"

TEST(KerberosTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/kerberos5.cap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_KERBEROS], (uint) 32);
}
