/**
 *  Test for Ethereum protocol.
 **/
#include "common.h"

TEST(EthereumTest, Generic) {
  std::vector<uint> protocols;
  getProtocols("./pcaps/ethereum.pcap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_JSON_RPC], (uint) 813);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_ETHEREUM], (uint) 813);
}

TEST(EthereumTest, JsonHTTP) {
  std::vector<uint> protocols;
  uint eth_json_http_pkts = 0;
  getProtocols("./pcaps/ethereum-js-http.pcap", protocols, NULL, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    if(r.l7.protocols_num >= 3 &&
       r.l7.protocols[0] == PFWL_PROTO_L7_HTTP &&
       r.l7.protocols[1] == PFWL_PROTO_L7_JSON_RPC &&
       r.l7.protocols[2] == PFWL_PROTO_L7_ETHEREUM){
      ++eth_json_http_pkts;
    }
  });
  EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 7);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_JSON_RPC], (uint) 7);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_ETHEREUM], (uint) 7);
  EXPECT_EQ(eth_json_http_pkts, (uint) 7);
}
