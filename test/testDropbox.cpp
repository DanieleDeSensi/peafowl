/**
 *  Test for Dropbox protocol.
 **/
#include "common.h"

TEST(DropboxTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/dropbox.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_DROPBOX], (uint) 12);
    getProtocols("./pcaps/dropbox_2.pcapng", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_DROPBOX], (uint) 12);
}
