/**
 *  Test for IP fragmentation.
 **/
#include "common.h"

static void test4in4(bool defrag){
  pfwl_state_t* state = pfwl_init();
  if(!defrag){
    pfwl_ipv4_fragmentation_disable(state);
    pfwl_ipv6_fragmentation_disable(state);
  }
  std::vector<uint> protocols;
  uint icmp_packets = 0;
  for(auto r : getProtocolsWithState("./pcaps/ip_fragmentation/4in4_outer.pcap", protocols, state)){
    if(r.protocol_l4 == IPPROTO_ICMP){
      ++icmp_packets;
    }
  }
  if(defrag){
    EXPECT_EQ(icmp_packets, (uint) 10);
  }else{
    EXPECT_EQ(icmp_packets, (uint) 0);
  }
  pfwl_terminate(state);
}

static void test6in6(bool defrag, const char* filename){
  pfwl_state_t* state = pfwl_init();
  if(!defrag){
    pfwl_ipv4_fragmentation_disable(state);
    pfwl_ipv6_fragmentation_disable(state);
  }
  std::vector<uint> protocols;
  bool checked = false;
  size_t packet_id = 1;
  std::vector<pfwl_dissection_info_t> results = getProtocolsWithState(filename, protocols, state);
  for(auto r : results){
    if(packet_id == results.size()){
      checked = true;
      if(defrag){
        uint expected_port = htons(1985);
        EXPECT_EQ(r.port_src, expected_port);
        EXPECT_EQ(r.port_dst, expected_port);
        struct sockaddr_in6 sa;
        inet_pton(AF_INET6, "0000:0000:0000:0000:0000:0000:ac10:c702", &(sa.sin6_addr));
        for(size_t i = 0; i < 16; i++){
          EXPECT_EQ(r.addr_src.ipv6.s6_addr[i], sa.sin6_addr.s6_addr[i]);
        }
        inet_pton(AF_INET6, "0000:0000:0000:0000:0000:0000:e000:0002", &(sa.sin6_addr));
        for(size_t i = 0; i < 16; i++){
          EXPECT_EQ(r.addr_dst.ipv6.s6_addr[i], sa.sin6_addr.s6_addr[i]);
        }
        EXPECT_EQ(r.protocol_l4, (uint) IPPROTO_UDP);
      }else{
        EXPECT_EQ(r.port_src, (uint) 0);
        EXPECT_EQ(r.port_dst, (uint) 0);
      }
    }
    ++packet_id;
  }
  EXPECT_TRUE(checked);
  pfwl_terminate(state);
}


static void testGeneric(bool defrag){
  pfwl_state_t* state = pfwl_init();
  if(!defrag){
    pfwl_ipv4_fragmentation_disable(state);
    pfwl_ipv6_fragmentation_disable(state);
  }
  std::vector<uint> protocols;
  std::vector<pfwl_dissection_info_t> results = getProtocolsWithState("./pcaps/ip_fragmentation/correct_1.pcap", protocols, state);
  size_t packet_id = 1;
  for(auto r : results){
    if(packet_id == results.size()){
      uint expected_port_src = 0;
      uint expected_port_dst = 0;
      if(defrag){
        expected_port_src = htons(47006);
        expected_port_dst = htons(5060);
      }

      EXPECT_EQ(r.port_src, expected_port_src);
      EXPECT_EQ(r.port_dst, expected_port_dst);
    }
    ++packet_id;
  }
  if(defrag){
    EXPECT_EQ(protocols[PFWL_PROTOCOL_SIP], (uint) 1);
  }else{
    EXPECT_EQ(protocols[PFWL_PROTOCOL_SIP], (uint) 0);
  }
  pfwl_terminate(state);
}


TEST(IPFragmentation, Generic) {
  testGeneric(true);
  testGeneric(false);
}

TEST(IPFragmentation, fourInFour) {
  test4in4(true);
  test4in4(false);
}

TEST(IPFragmentation, sixInSixBoth) {
  test6in6(true, "./pcaps/ip_fragmentation/6in6_both.pcap");
  test6in6(false, "./pcaps/ip_fragmentation/6in6_both.pcap");
}

TEST(IPFragmentation, sixInSixInner) {
  test6in6(true, "./pcaps/ip_fragmentation/6in6_inner.pcap");
  test6in6(false, "./pcaps/ip_fragmentation/6in6_inner.pcap");
}

TEST(IPFragmentation, overlapping) {
  std::vector<uint> protocols;
  getProtocols("./pcaps/ip_fragmentation/overlapping.pcap", protocols);
}

#if 0
TEST(IPFragmentation, teardrop) {
  std::vector<uint> protocols;
  std::vector<pfwl_dissection_info_t> results = getProtocols("./pcaps/ip_fragmentation/teardrop.pcap", protocols);
  size_t packet_id = 1;
  for(auto r : results){
    if(packet_id == results.size()){
      uint expected_port_src = htons(31915);
      uint expected_port_dst = htons(20197);
      EXPECT_EQ(r.port_src, expected_port_src);
      EXPECT_EQ(r.port_dst, expected_port_dst);
      EXPECT_EQ(r.protocol_l4, IPPROTO_UDP);
    }
    ++packet_id;
  }
}
#endif

