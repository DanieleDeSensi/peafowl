/**
 *  Statistics tests.
 **/
#include "common.h"
#include <time.h>

const double expected_ts[2][10] = {{0}, 
                                   {0.000000, 130187.000000, 630907.000000, 110159.000000, 80115.000000, 260374.000000, 480691.000000, 120173.000000, 140202.000000, 470677.000000}};
const double expected_lengths[2][10] = {{479},
                                        {1380, 1380, 1380, 1380, 1380, 1380, 1380, 1380, 1380, 1380}};

static uint32_t targetflow = 0;
void splt(pfwl_flow_info_t* flow_info){
  if(flow_info->id == targetflow){
    EXPECT_EQ(flow_info->splt_stored_records[0], 1);
    EXPECT_EQ(flow_info->splt_stored_records[1], 10);
    for(uint8_t dir = 0; dir < 2; dir++){
      for(uint8_t id = 0; id < flow_info->splt_stored_records[dir]; id++){
        EXPECT_EQ(flow_info->splt_times[id][dir], expected_ts[dir][id]);
        EXPECT_EQ(flow_info->splt_lengths[id][dir], expected_lengths[dir][id]);
      }
    }
  }
}

TEST(SPLTTest, SPLT) {
  pfwl_state_t* state = pfwl_init();
  pfwl_set_flow_termination_callback(state, &splt);
  pfwl_set_timestamp_unit(state, PFWL_TIMESTAMP_UNIT_MICROSECONDS); // Since we set PCAP timestamps (which are expressed as microseconds).
  std::vector<uint> protocols;
  targetflow = 0;
  getProtocols("./pcaps/http.cap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    ;
  }, true);
  pfwl_terminate(state);
}
