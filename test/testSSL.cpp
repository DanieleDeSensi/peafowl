/**
 *  Test for SSL protocol.
 **/
#include "common.h"

TEST(SSLTest, DeprecatedCalls) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    getProtocolsOld("./pcaps/ssl.pcapng", tcpProtocols, udpProtocols);
    EXPECT_EQ(tcpProtocols[DPI_PROTOCOL_TCP_SSL], (uint) 840);
}

TEST(SSLTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/ssl.pcapng", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_SSL], (uint) 840);
    getProtocols("./pcaps/6in4tunnel.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_SSL], (uint) 54);
    getProtocols("./pcaps/dropbox.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_SSL], (uint) 224);
    getProtocols("./pcaps/spotify.pcapng", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_SSL], (uint) 11);
}
