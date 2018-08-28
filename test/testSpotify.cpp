/**
 *  Test for Spotify protocol.
 **/
#include "common.h"

TEST(SpotifyTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/spotify.pcapng", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_SPOTIFY], (uint) 437);
}
