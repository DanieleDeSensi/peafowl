/**
 *  Test for L3 dissection.
 **/
#include "common.h"

TEST(L3Dissection, 4in4) {
  pfwl_state_t* state = pfwl_init();
  std::vector<uint> protocols;
  size_t packet_id = 1;
  size_t icmp_packets = 0;
  getProtocols("./pcaps/L3/4in4.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    struct sockaddr_in src, dst;
    inet_pton(AF_INET, "1.1.1.1", &(src.sin_addr));
    inet_pton(AF_INET, "2.2.2.2", &(dst.sin_addr));
    if(!(packet_id % 2)){
      uint32_t tmp = dst.sin_addr.s_addr;
      dst.sin_addr.s_addr = src.sin_addr.s_addr;
      src.sin_addr.s_addr = tmp;
    }
    EXPECT_EQ(src.sin_addr.s_addr, r.l3.addr_src.ipv4);
    EXPECT_EQ(dst.sin_addr.s_addr, r.l3.addr_dst.ipv4);
    if(r.l4.protocol == IPPROTO_ICMP){
      ++icmp_packets;
    }
    ++packet_id;
  });
  EXPECT_EQ(icmp_packets, packet_id - 1);
  pfwl_terminate(state);
}

TEST(L3Dissection, 4in6){
  pfwl_state_t* state = pfwl_init();
  std::vector<uint> protocols;
  size_t id = 0;
  getProtocols("./pcaps/L3/4in6.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    if(id == 0){
      struct sockaddr_in src, dst;
      inet_pton(AF_INET, "70.55.213.211", &(src.sin_addr));
      inet_pton(AF_INET, "192.88.99.1", &(dst.sin_addr));
      EXPECT_EQ(src.sin_addr.s_addr, r.l3.addr_src.ipv4);
      EXPECT_EQ(dst.sin_addr.s_addr, r.l3.addr_dst.ipv4);
      EXPECT_EQ(r.l4.port_src, (uint) ntohs(31337));
      EXPECT_EQ(r.l4.port_dst, (uint) ntohs(80));
      EXPECT_EQ(r.l4.protocol, IPPROTO_TCP);
      id = 1;
    }
  });
  pfwl_terminate(state);
}

TEST(L3Dissection, 6in4){
  pfwl_state_t* state = pfwl_init();
  std::vector<uint> protocols;
  size_t id = 0;
  getProtocols("./pcaps/L3/6in4.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    if(id == 0){
      struct sockaddr_in6 src, dst;
      inet_pton(AF_INET6, "2002:4637:d5d3:0000:0000:0000:4637:d5d3", &(src.sin6_addr));
      inet_pton(AF_INET6, "2001:4860:0000:2001:0000:0000:0000:0068", &(dst.sin6_addr));
      for(size_t i = 0; i < 16; i++){
        EXPECT_EQ(src.sin6_addr.s6_addr[i], r.l3.addr_src.ipv6.s6_addr[i]);
        EXPECT_EQ(dst.sin6_addr.s6_addr[i], r.l3.addr_dst.ipv6.s6_addr[i]);
      }
      EXPECT_EQ(r.l4.port_src, (uint) ntohs(31337));
      EXPECT_EQ(r.l4.port_dst, (uint) ntohs(80));
      EXPECT_EQ(r.l4.protocol, IPPROTO_TCP);
      id = 1;
    }
  });
  pfwl_terminate(state);
}

TEST(L3Dissection, ipv6_hdr_dstopts){
  pfwl_state_t* state = pfwl_init();
  std::vector<uint> protocols;
  size_t id = 0;
  getProtocols("./pcaps/L3/ipv6_hdr_dstopt.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    if(id == 0){
      struct sockaddr_in6 src, dst;
      inet_pton(AF_INET6, "2a01:0e35:8bd9:8bb0:a0a7:ea9c:74e8:d397", &(src.sin6_addr));
      inet_pton(AF_INET6, "2001:4b98:0dc0:0041:0216:3eff:fece:1902", &(dst.sin6_addr));
      for(size_t i = 0; i < 16; i++){
        EXPECT_EQ(src.sin6_addr.s6_addr[i], r.l3.addr_src.ipv6.s6_addr[i]);
        EXPECT_EQ(dst.sin6_addr.s6_addr[i], r.l3.addr_dst.ipv6.s6_addr[i]);
      }
      EXPECT_EQ(r.l4.port_src, (uint) ntohs(42513));
      EXPECT_EQ(r.l4.port_dst, (uint) ntohs(42));
      EXPECT_EQ(r.l4.protocol, IPPROTO_UDP);
      id = 1;
    }
  });
  pfwl_terminate(state);
}


TEST(L3Dissection, ipv6_hdr_hopbyhop){
  pfwl_state_t* state = pfwl_init();
  std::vector<uint> protocols;
  size_t id = 0;
  getProtocols("./pcaps/L3/ipv6_hdr_hopbyhop.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    if(id == 0){
      struct sockaddr_in6 src, dst;
      inet_pton(AF_INET6, "fe80:0000:0000:0000:021b:63ff:fe94:b10e", &(src.sin6_addr));
      inet_pton(AF_INET6, "ff02:0000:0000:0000:0000:0001:ff94:b10e", &(dst.sin6_addr));
      for(size_t i = 0; i < 16; i++){
        EXPECT_EQ(src.sin6_addr.s6_addr[i], r.l3.addr_src.ipv6.s6_addr[i]);
        EXPECT_EQ(dst.sin6_addr.s6_addr[i], r.l3.addr_dst.ipv6.s6_addr[i]);
      }
      EXPECT_EQ(r.l4.port_src, (uint) ntohs(0));
      EXPECT_EQ(r.l4.port_dst, (uint) ntohs(0));
      EXPECT_EQ(r.l4.protocol, IPPROTO_ICMPV6);
      id = 1;
    }
  });
  pfwl_terminate(state);
}

TEST(L3Dissection, ipv6_hdr_routing){
  pfwl_state_t* state = pfwl_init();
  std::vector<uint> protocols;
  size_t id = 0;
  getProtocols("./pcaps/L3/ipv6_hdr_routing.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    if(id == 0){
      struct sockaddr_in6 src, dst;
      inet_pton(AF_INET6, "3001:0000:0000:0000:0200:10ff:fe10:1181", &(src.sin6_addr));
      inet_pton(AF_INET6, "3000:0000:0000:0000:0215:17ff:fe16:c7fe", &(dst.sin6_addr));
      for(size_t i = 0; i < 16; i++){
        EXPECT_EQ(src.sin6_addr.s6_addr[i], r.l3.addr_src.ipv6.s6_addr[i]);
        EXPECT_EQ(dst.sin6_addr.s6_addr[i], r.l3.addr_dst.ipv6.s6_addr[i]);
      }
      EXPECT_EQ(r.l4.port_src, (uint) ntohs(0));
      EXPECT_EQ(r.l4.port_dst, (uint) ntohs(0));
      EXPECT_EQ(r.l4.protocol, IPPROTO_ICMPV6);
      id = 1;
    }
  });
  pfwl_terminate(state);
}

TEST(L3Dissection, rsvp){
  pfwl_state_t* state = pfwl_init();
  std::vector<uint> protocols;
  size_t id = 0;
  getProtocols("./pcaps/L3/rsvp.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    if(id == 0){
      struct sockaddr_in src, dst;
      inet_pton(AF_INET, "10.1.24.4", &(src.sin_addr));
      inet_pton(AF_INET, "10.1.12.1", &(dst.sin_addr));
      EXPECT_EQ(src.sin_addr.s_addr, r.l3.addr_src.ipv4);
      EXPECT_EQ(dst.sin_addr.s_addr, r.l3.addr_dst.ipv4);
      EXPECT_EQ(r.l4.port_src, (uint) ntohs(0));
      EXPECT_EQ(r.l4.port_dst, (uint) ntohs(0));
      EXPECT_EQ(r.l4.protocol, IPPROTO_RSVP);
      id = 1;
    }
  });
  pfwl_terminate(state);
}


TEST(L3Dissection, truncated){
  const char* truncated_files[] = {"./pcaps/L3/truncated_tcp.pcap", "./pcaps/L3/truncated_udp.pcap", "./pcaps/L3/truncated_icmp.pcap", "./pcaps/L3/truncated_ip.pcap"};
  for(auto filename : truncated_files){
    pfwl_state_t* state = pfwl_init();
    std::vector<uint> protocols;
    getProtocols(filename, protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
      if(strstr(filename, "_ip.pcap") || strstr(filename, "_icmp.pcap")){
        EXPECT_EQ(status, PFWL_ERROR_L3_PARSING);
      }else{
        EXPECT_EQ(status, PFWL_ERROR_L4_PARSING);
      }
    });

    pfwl_terminate(state);
  }
}

TEST(L3Dissection, igmp){
  pfwl_state_t* state = pfwl_init();
  std::vector<uint> protocols;
  size_t id = 0;
  getProtocols("./pcaps/L3/igmp.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    if(id == 0){
      struct sockaddr_in src, dst;
      inet_pton(AF_INET, "192.168.2.5", &(src.sin_addr));
      inet_pton(AF_INET, "224.0.0.22", &(dst.sin_addr));
      EXPECT_EQ(src.sin_addr.s_addr, r.l3.addr_src.ipv4);
      EXPECT_EQ(dst.sin_addr.s_addr, r.l3.addr_dst.ipv4);
      EXPECT_EQ(r.l4.port_src, (uint) ntohs(0));
      EXPECT_EQ(r.l4.port_dst, (uint) ntohs(0));
      EXPECT_EQ(r.l4.protocol, IPPROTO_IGMP);
      id = 1;
    }
  });
  pfwl_terminate(state);
}
