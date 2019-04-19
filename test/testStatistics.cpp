/**
 *  Statistics tests.
 **/
#include "common.h"
#include <time.h>

TEST(StatisticsTest, Timestamps) {
  pfwl_state_t* state = pfwl_init();
  std::vector<uint> protocols;
  uint32_t last_timestamp = 0;
  uint8_t check_timestamp = 1;
  uint8_t direction;
  uint8_t slept = 0;
  getProtocols("./pcaps/http-jpeg.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    if(last_timestamp && check_timestamp && r.l4.direction == direction){
      EXPECT_TRUE(r.flow_info.statistics[PFWL_STAT_TIMESTAMP_LAST][direction] - r.flow_info.statistics[PFWL_STAT_TIMESTAMP_FIRST][direction] == 2 ||
                  r.flow_info.statistics[PFWL_STAT_TIMESTAMP_LAST][direction] - r.flow_info.statistics[PFWL_STAT_TIMESTAMP_FIRST][direction] == 3);
      EXPECT_TRUE(r.flow_info.statistics[PFWL_STAT_L4_TCP_RTT_SYN_ACK][0] == 2 ||
                  r.flow_info.statistics[PFWL_STAT_L4_TCP_RTT_SYN_ACK][0] == 3);
      EXPECT_TRUE(r.flow_info.statistics[PFWL_STAT_L4_TCP_RTT_SYN_ACK][1] == 0);
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

TEST(StatisticsTest, BytesAndPackets) {
  pfwl_state_t* state = pfwl_init();
  std::vector<uint> protocols;
  size_t packet_id = 1; // Starts from one for a simple comparison with wireshark output
  getProtocols("./pcaps/http.cap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    if(packet_id == 3){
      // src -> dst
      EXPECT_EQ(r.flow_info.statistics[PFWL_STAT_BYTES][0], 88);
      EXPECT_EQ(r.flow_info.statistics[PFWL_STAT_PACKETS][0], 2);
      EXPECT_EQ(r.flow_info.statistics[PFWL_STAT_L7_BYTES][0], 0);
      EXPECT_EQ(r.flow_info.statistics[PFWL_STAT_L7_PACKETS][0], 0);
      // dst -> src
      EXPECT_EQ(r.flow_info.statistics[PFWL_STAT_BYTES][1], 48);
      EXPECT_EQ(r.flow_info.statistics[PFWL_STAT_PACKETS][1], 1);
      EXPECT_EQ(r.flow_info.statistics[PFWL_STAT_L7_BYTES][1], 0);
      EXPECT_EQ(r.flow_info.statistics[PFWL_STAT_L7_PACKETS][1], 0);
    }else if(packet_id == 6){
      // src -> dst
      EXPECT_EQ(r.flow_info.statistics[PFWL_STAT_BYTES][0], 128 + 479);
      EXPECT_EQ(r.flow_info.statistics[PFWL_STAT_PACKETS][0], 3);
      EXPECT_EQ(r.flow_info.statistics[PFWL_STAT_L7_BYTES][0], 479);
      EXPECT_EQ(r.flow_info.statistics[PFWL_STAT_L7_PACKETS][0], 1);
      // dst -> src
      EXPECT_EQ(r.flow_info.statistics[PFWL_STAT_BYTES][1], 128 + 1380);
      EXPECT_EQ(r.flow_info.statistics[PFWL_STAT_PACKETS][1], 3);
      EXPECT_EQ(r.flow_info.statistics[PFWL_STAT_L7_BYTES][1], 1380);
      EXPECT_EQ(r.flow_info.statistics[PFWL_STAT_L7_PACKETS][1], 1);
    }
    ++packet_id;
  });
  pfwl_terminate(state);
}

static double syn_found[2], fin_found[2], rst_found[2], retrans[2], zerowin[2], winscaling[2];
static uint32_t targetflow = 0;
void flagchecker(pfwl_flow_info_t* flow_info){
  if(flow_info->id == targetflow){
    syn_found[0] = flow_info->statistics[PFWL_STAT_L4_TCP_COUNT_SYN][0];
    syn_found[1] = flow_info->statistics[PFWL_STAT_L4_TCP_COUNT_SYN][1];

    fin_found[0] = flow_info->statistics[PFWL_STAT_L4_TCP_COUNT_FIN][0];
    fin_found[1] = flow_info->statistics[PFWL_STAT_L4_TCP_COUNT_FIN][1];

    rst_found[0] = flow_info->statistics[PFWL_STAT_L4_TCP_COUNT_RST][0];
    rst_found[1] = flow_info->statistics[PFWL_STAT_L4_TCP_COUNT_RST][1];

    retrans[0] = flow_info->statistics[PFWL_STAT_L4_TCP_COUNT_RETRANSMISSIONS][0];
    retrans[1] = flow_info->statistics[PFWL_STAT_L4_TCP_COUNT_RETRANSMISSIONS][1];

    zerowin[0] = flow_info->statistics[PFWL_STAT_L4_TCP_COUNT_ZERO_WINDOW][0];
    zerowin[1] = flow_info->statistics[PFWL_STAT_L4_TCP_COUNT_ZERO_WINDOW][1];

    winscaling[0] = flow_info->statistics[PFWL_STAT_L4_TCP_WINDOW_SCALING][0];
    winscaling[1] = flow_info->statistics[PFWL_STAT_L4_TCP_WINDOW_SCALING][1];
  }
}

TEST(StatisticsTest, TCPFlags) {
  pfwl_state_t* state = pfwl_init();
  pfwl_statistic_add(state, PFWL_STAT_L4_TCP_COUNT_SYN);
  pfwl_statistic_add(state, PFWL_STAT_L4_TCP_COUNT_FIN);
  pfwl_statistic_add(state, PFWL_STAT_L4_TCP_COUNT_RST);
  pfwl_set_flow_termination_callback(state, &flagchecker);
  std::vector<uint> protocols;
  targetflow = 0;
  getProtocols("./pcaps/http.cap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    ;
  });
  pfwl_terminate(state);
  EXPECT_EQ(syn_found[0], 1);
  EXPECT_EQ(syn_found[1], 1);
  EXPECT_EQ(fin_found[0], 1);
  EXPECT_EQ(fin_found[1], 1);
  EXPECT_EQ(rst_found[0], 0);
  EXPECT_EQ(rst_found[1], 0);
}

TEST(StatisticsTest, TCPFlags2) {
  pfwl_state_t* state = pfwl_init();
  pfwl_statistic_add(state, PFWL_STAT_L4_TCP_COUNT_SYN);
  pfwl_statistic_add(state, PFWL_STAT_L4_TCP_COUNT_FIN);
  pfwl_statistic_add(state, PFWL_STAT_L4_TCP_COUNT_RST);
  pfwl_set_flow_termination_callback(state, &flagchecker);
  pfwl_tcp_reordering_disable(state);
  std::vector<uint> protocols;
  targetflow = 0;
  getProtocols("./pcaps/http-segmented.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    ;
  });
  pfwl_terminate(state);
  EXPECT_EQ(syn_found[0], 1);
  EXPECT_EQ(syn_found[1], 1);
  EXPECT_EQ(fin_found[0], 0);
  EXPECT_EQ(fin_found[1], 0);
  EXPECT_EQ(rst_found[0], 0);
  EXPECT_EQ(rst_found[1], 1);
}

TEST(StatisticsTest, TCPRetransmissions) {
  retrans[0] = 0;
  retrans[1] = 0;
  pfwl_state_t* state = pfwl_init();
  pfwl_statistic_add(state, PFWL_STAT_L4_TCP_COUNT_RETRANSMISSIONS);
  pfwl_set_flow_termination_callback(state, &flagchecker);
  std::vector<uint> protocols;
  targetflow = 2;
  getProtocols("./pcaps/http.cap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    ;
  });
  pfwl_terminate(state);
  EXPECT_EQ(retrans[0], 1);
  EXPECT_EQ(retrans[1], 1);
}

TEST(StatisticsTest, TCPZeroWindow) {
  pfwl_state_t* state = pfwl_init();
  pfwl_statistic_add(state, PFWL_STAT_L4_TCP_COUNT_ZERO_WINDOW);
  pfwl_set_flow_termination_callback(state, &flagchecker);
  std::vector<uint> protocols;
  targetflow = 0;
  getProtocols("./pcaps/http-jpeg.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    ;
  });
  pfwl_terminate(state);
  EXPECT_EQ(zerowin[0], 1);
  EXPECT_EQ(zerowin[1], 0);
}

TEST(StatisticsTest, TCPWindowScaling) {
  pfwl_state_t* state = pfwl_init();
  pfwl_statistic_add(state, PFWL_STAT_L4_TCP_WINDOW_SCALING);
  pfwl_set_flow_termination_callback(state, &flagchecker);
  std::vector<uint> protocols;
  targetflow = 0;
  getProtocols("./pcaps/http-segmented.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    ;
  });
  pfwl_terminate(state);
  EXPECT_EQ(winscaling[0], 7);
  EXPECT_EQ(winscaling[1], 0);
}

TEST(StatisticsTest, TCPNoWindowScaling) {
  pfwl_state_t* state = pfwl_init();
  pfwl_statistic_add(state, PFWL_STAT_L4_TCP_WINDOW_SCALING);
  pfwl_set_flow_termination_callback(state, &flagchecker);
  std::vector<uint> protocols;
  targetflow = 0;
  getProtocols("./pcaps/http.cap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    ;
  });
  pfwl_terminate(state);
  EXPECT_EQ(winscaling[0], -1);
  EXPECT_EQ(winscaling[1], -1);
}
