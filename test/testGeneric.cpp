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
