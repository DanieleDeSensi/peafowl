/**
 *  Test for Dropbox protocol.
 **/
#include "common.h"

TEST(DropboxTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/dropbox_old.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_DROPBOX], (uint) 12);
    getProtocols("./pcaps/dropbox.pcapng", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_DROPBOX], (uint) 12);
}
