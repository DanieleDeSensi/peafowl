/**
 *  Generic tests.
 **/
#include "common.h"
#include <time.h>

TEST(GenericTest, Timestamps) {
  pfwl_state_t* state = pfwl_init();
  std::vector<uint> protocols;
  uint32_t last_timestamp = 0;
  uint8_t check_timestamp = 1;
  uint8_t direction;
  uint8_t slept = 0;
  getProtocols("./pcaps/http-jpeg.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    if(last_timestamp && check_timestamp && r.l4.direction == direction){
      EXPECT_TRUE(r.flow_info.timestamp_last[direction] - r.flow_info.timestamp_first[direction] == 2 ||
                  r.flow_info.timestamp_last[direction] - r.flow_info.timestamp_first[direction] == 3);
      check_timestamp = 0;
    }else if(!slept){
      direction = r.l4.direction;
      last_timestamp = r.flow_info.timestamp_last[direction];
      slept = 1;
      sleep(3);
    }
  });
  pfwl_terminate(state);
}

TEST(GenericTest, BytesAndPackets) {
  pfwl_state_t* state = pfwl_init();
  std::vector<uint> protocols;
  size_t packet_id = 1; // Starts from one for a simple comparison with wireshark output
  getProtocols("./pcaps/http.cap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    if(packet_id == 3){
      // src -> dst
      EXPECT_EQ(r.flow_info.num_bytes[0], 88);
      EXPECT_EQ(r.flow_info.num_packets[0], 2);
      EXPECT_EQ(r.flow_info.num_bytes_l7[0], 0);
      EXPECT_EQ(r.flow_info.num_packets_l7[0], 0);
      // dst -> src
      EXPECT_EQ(r.flow_info.num_bytes[1], 48);
      EXPECT_EQ(r.flow_info.num_packets[1], 1);
      EXPECT_EQ(r.flow_info.num_bytes_l7[1], 0);
      EXPECT_EQ(r.flow_info.num_packets_l7[1], 0);
    }else if(packet_id == 6){
      // src -> dst
      EXPECT_EQ(r.flow_info.num_bytes[0], 128 + 479);
      EXPECT_EQ(r.flow_info.num_packets[0], 3);
      EXPECT_EQ(r.flow_info.num_bytes_l7[0], 479);
      EXPECT_EQ(r.flow_info.num_packets_l7[0], 1);
      // dst -> src
      EXPECT_EQ(r.flow_info.num_bytes[1], 128 + 1380);
      EXPECT_EQ(r.flow_info.num_packets[1], 3);
      EXPECT_EQ(r.flow_info.num_bytes_l7[1], 1380);
      EXPECT_EQ(r.flow_info.num_packets_l7[1], 1);
    }
    ++packet_id;
  });
  pfwl_terminate(state);
}


TEST(GenericTest, MaxFlows) {
  pfwl_state_t* state = pfwl_init();
  std::vector<uint> protocols;
  pfwl_set_expected_flows(state, 1, 1);
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
  EXPECT_EQ(protocols[PFWL_PROTO_L7_IMAP], 0);
  pfwl_terminate(state);
}


TEST(GenericTest, NullState) {
  EXPECT_EQ(pfwl_set_expected_flows(NULL, 0, 0), 1);
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
    EXPECT_STREQ(pfwl_get_L7_field_name(PFWL_FIELDS_L7_HTTP_BODY), "HTTP_BODY");
}