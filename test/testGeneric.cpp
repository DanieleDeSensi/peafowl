/**
 *  Generic tests.
 **/
#include "common.h"
#include <time.h>

TEST(GenericTest, MaxFlows) {
  pfwl_state_t* state = pfwl_init();
  std::vector<uint> protocols;
  pfwl_set_expected_flows(state, 1, PFWL_FLOWS_STRATEGY_SKIP);
  uint errors = 0;
  getProtocols("./pcaps/whatsapp.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    if(status == PFWL_ERROR_MAX_FLOWS){
      ++errors;
    }
  });
  EXPECT_GT(errors, 0);
  pfwl_terminate(state);
}

TEST(GenericTest, MaxTrials) {
  pfwl_state_t* state = pfwl_init();
  std::vector<uint> protocols;
  pfwl_set_max_trials(state, 1);
  getProtocols("./pcaps/imap.cap", protocols, state);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_IMAP], 5);
  pfwl_terminate(state);
}


TEST(GenericTest, NullState) {
  EXPECT_EQ(pfwl_set_expected_flows(NULL, 0, PFWL_FLOWS_STRATEGY_NONE), 1);
  EXPECT_EQ(pfwl_set_max_trials(NULL, 0), 1);
  EXPECT_EQ(pfwl_defragmentation_enable_ipv4(NULL, 0), 1);
  EXPECT_EQ(pfwl_defragmentation_enable_ipv6(NULL, 0), 1);
  EXPECT_EQ(pfwl_defragmentation_set_per_host_memory_limit_ipv4(NULL, 0), 1);
  EXPECT_EQ(pfwl_defragmentation_set_per_host_memory_limit_ipv6(NULL, 0), 1);
  EXPECT_EQ(pfwl_defragmentation_set_total_memory_limit_ipv4(NULL, 0), 1);
  EXPECT_EQ(pfwl_defragmentation_set_total_memory_limit_ipv6(NULL, 0), 1);
  EXPECT_EQ(pfwl_defragmentation_set_reassembly_timeout_ipv4(NULL, 0), 1);
  EXPECT_EQ(pfwl_defragmentation_set_reassembly_timeout_ipv6(NULL, 0), 1);
  EXPECT_EQ(pfwl_defragmentation_disable_ipv4(NULL), 1);
  EXPECT_EQ(pfwl_defragmentation_disable_ipv6(NULL), 1);
  EXPECT_EQ(pfwl_tcp_reordering_enable(NULL), 1);
  EXPECT_EQ(pfwl_tcp_reordering_disable(NULL), 1);
  EXPECT_EQ(pfwl_protocol_l7_enable(NULL, PFWL_PROTO_L7_BGP), 1);
  EXPECT_EQ(pfwl_protocol_l7_disable(NULL, PFWL_PROTO_L7_BGP), 1);
  EXPECT_EQ(pfwl_protocol_l7_enable_all(NULL), 1);
  EXPECT_EQ(pfwl_protocol_l7_disable_all(NULL), 1);
  EXPECT_EQ(pfwl_set_flow_cleaner_callback(NULL, NULL), 1);
  EXPECT_EQ(pfwl_field_add_L7(NULL, PFWL_FIELDS_L7_DNS_AUTH_SRV), 1);
  EXPECT_EQ(pfwl_field_remove_L7(NULL, PFWL_FIELDS_L7_DNS_AUTH_SRV), 1);
  EXPECT_EQ(pfwl_set_protocol_accuracy_L7(NULL, PFWL_PROTO_L7_BGP, PFWL_DISSECTOR_ACCURACY_HIGH), 1);
}

TEST(GenericTest, FieldNamesConversion) {
  EXPECT_STREQ(pfwl_get_L7_field_name(PFWL_FIELDS_L7_NUM), "NUM");
  EXPECT_STREQ(pfwl_get_L7_field_name(PFWL_FIELDS_L7_HTTP_BODY), "BODY");
  EXPECT_EQ(pfwl_get_L7_field_id(PFWL_PROTO_L7_SSL, "CERTIFICATE"), PFWL_FIELDS_L7_SSL_CERTIFICATE);
  EXPECT_EQ(pfwl_get_L7_field_id(PFWL_PROTO_L7_HTTP, "URL"), PFWL_FIELDS_L7_HTTP_URL);
}

TEST(GenericTest, ProtoL2NamesConversion) {
  EXPECT_STREQ(pfwl_get_L2_protocol_name(PFWL_PROTO_L2_FDDI), "FDDI");
  EXPECT_EQ(pfwl_get_L2_protocol_id("EN10MB"), PFWL_PROTO_L2_EN10MB);
}

TEST(GenericTest, ProtoL3NamesConversion) {
  EXPECT_STREQ(pfwl_get_L3_protocol_name(PFWL_PROTO_L3_IPV4), "IPv4");
  EXPECT_EQ(pfwl_get_L3_protocol_id("IPv6"), PFWL_PROTO_L3_IPV6);
}

TEST(GenericTest, ProtoL4NamesConversion) {
  EXPECT_STREQ(pfwl_get_L4_protocol_name(IPPROTO_TCP), "TCP");
  EXPECT_EQ(pfwl_get_L4_protocol_id("UDP"), IPPROTO_UDP);
}

TEST(GenericTest, ProtoL7NamesConversion) {
  EXPECT_STREQ(pfwl_get_L7_protocol_name(PFWL_PROTO_L7_JSON_RPC), "JSON-RPC");
  EXPECT_EQ(pfwl_get_L7_protocol_id("QUIC"), PFWL_PROTO_L7_QUIC);
}
