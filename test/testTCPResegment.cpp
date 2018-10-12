/**
 *  Test for TCP resegmentation.
 **/
#include "common.h"

TEST(TCPResegmentation, Generic) {
    const char* filenames[] = {"./pcaps/tcp_resegment/http_ip_fragmented_out_of_order.pcap",
                               "./pcaps/tcp_resegment/http_ip_fragmented.pcap",
                               "./pcaps/tcp_resegment/http_no_syn.pcap",
                               "./pcaps/tcp_resegment/http_no_syn_synack_ack.pcap",
                               "./pcaps/tcp_resegment/http_out_of_order_1.pcap",
                               "./pcaps/tcp_resegment/http_out_of_order_2.pcap",
                               "./pcaps/tcp_resegment/http_seq_num_wrapping_out_of_order.pcap",
                               "./pcaps/tcp_resegment/http_seq_num_wrapping.pcap",};
    uint expected_http_packets[] = {8, 8, 8, 3, 9, 5, 6, 8};
    uint expected_http_packets_without_reordering[] = {8, 8, 8, 8, 9, 6, 7, 8};
    size_t numtests = sizeof(expected_http_packets) / sizeof(expected_http_packets[0]);
    for(size_t i = 0; i < numtests; i++){
      std::vector<uint> protocols;
      pfwl_state* state = pfwl_init();
      getProtocols(filenames[i], protocols, state);
      EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], expected_http_packets[i]);

      pfwl_terminate(state);
    }


    for(size_t i = 0; i < numtests; i++){
      std::vector<uint> protocols;
      pfwl_state* state = pfwl_init();
      pfwl_tcp_reordering_disable(state);
      getProtocols(filenames[i], protocols, state);
      EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], expected_http_packets_without_reordering[i]);

      pfwl_terminate(state);
    }
}
