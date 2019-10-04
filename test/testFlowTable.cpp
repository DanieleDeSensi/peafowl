/**
 *  Test for L3 dissection.
 **/
#include "common.h"
#include <peafowl/flow_table.h>

static pfwl_dissection_info_t initPktInfo(uint id, pfwl_direction_t dir){
  pfwl_dissection_info_t r;
  r.l2.length = 0;
  r.l3.length = 0;
  r.l3.addr_src.ipv4 = id;
  r.l3.addr_dst.ipv4 = id;
  r.l3.protocol = PFWL_PROTO_L3_IPV4;
  r.l4.length = 0;
  r.l4.payload_length = 100;
  r.l4.port_src = id;
  r.l4.port_dst = id;
  r.l4.direction = dir;
  r.l4.protocol = IPPROTO_TCP;
  return r;
}

TEST(FlowTable, MaxFlows) {
  pfwl_flow_table_t* table = pfwl_flow_table_create(PFWL_DEFAULT_FLOW_TABLE_AVG_BUCKET_SIZE, PFWL_FLOWS_STRATEGY_SKIP, 1);
  char protos[128];
  memset(protos, 0, sizeof(protos));
  uint32_t ts = 0;
  pfwl_dissection_info_t p;

  p = initPktInfo(0, PFWL_DIRECTION_OUTBOUND);
  pfwl_flow_t* f1 = pfwl_flow_table_find_or_create_flow(table, &p, protos, 0, ts, 0, PFWL_TIMESTAMP_UNIT_SECONDS);
  EXPECT_TRUE(f1 != NULL);
  
  for(size_t i = 1; i < PFWL_DEFAULT_FLOW_TABLE_AVG_BUCKET_SIZE; i++){
    ++ts;
    p = initPktInfo(i, PFWL_DIRECTION_OUTBOUND);
    pfwl_flow_t* fi = pfwl_flow_table_find_or_create_flow(table, &p, protos, 0, ts, 0, PFWL_TIMESTAMP_UNIT_SECONDS);
    EXPECT_TRUE(fi != NULL);
  }

  ++ts;
  p = initPktInfo(0, PFWL_DIRECTION_INBOUND);
  pfwl_flow_t* f1_1 = pfwl_flow_table_find_or_create_flow(table, &p, protos, 0, ts, 0, PFWL_TIMESTAMP_UNIT_SECONDS);
  EXPECT_TRUE(f1_1 == f1);
  
  ++ts;
  p = initPktInfo(PFWL_DEFAULT_FLOW_TABLE_AVG_BUCKET_SIZE, PFWL_DIRECTION_OUTBOUND);
  pfwl_flow_t* fn = pfwl_flow_table_find_or_create_flow(table, &p, protos, 0, ts, 0, PFWL_TIMESTAMP_UNIT_SECONDS);
  EXPECT_TRUE(fn == NULL);
}

static uint32_t evictedId = 9999;
static void flowCb(pfwl_flow_info_t* flow_info){
  evictedId = flow_info->id;
}

TEST(FlowTable, MaxFlowsEviction) {
  pfwl_flow_table_t* table = pfwl_flow_table_create(PFWL_DEFAULT_FLOW_TABLE_AVG_BUCKET_SIZE, PFWL_FLOWS_STRATEGY_EVICT, 1);
  pflw_flow_table_set_flow_termination_callback(table, flowCb);
  char protos[128];
  memset(protos, 0, sizeof(protos));
  uint32_t ts = 0;
  pfwl_dissection_info_t p;

  p = initPktInfo(0, PFWL_DIRECTION_OUTBOUND);
  pfwl_flow_t* f1 = pfwl_flow_table_find_or_create_flow(table, &p, protos, 0, ts, 0, PFWL_TIMESTAMP_UNIT_SECONDS);
  EXPECT_TRUE(f1 != NULL);
 
  for(size_t i = 1; i < PFWL_DEFAULT_FLOW_TABLE_AVG_BUCKET_SIZE; i++){
    ++ts;
    p = initPktInfo(i, PFWL_DIRECTION_OUTBOUND);
    pfwl_flow_t* fi = pfwl_flow_table_find_or_create_flow(table, &p, protos, 0, ts, 0, PFWL_TIMESTAMP_UNIT_SECONDS);
    EXPECT_TRUE(fi != NULL);
  }

  ++ts;
  p = initPktInfo(0, PFWL_DIRECTION_INBOUND);
  pfwl_flow_t* f1_1 = pfwl_flow_table_find_or_create_flow(table, &p, protos, 0, ts, 0, PFWL_TIMESTAMP_UNIT_SECONDS);
  EXPECT_TRUE(f1_1 == f1);
  
  ++ts;
  p = initPktInfo(PFWL_DEFAULT_FLOW_TABLE_AVG_BUCKET_SIZE, PFWL_DIRECTION_OUTBOUND);
  pfwl_flow_t* fn = pfwl_flow_table_find_or_create_flow(table, &p, protos, 0, ts, 0, PFWL_TIMESTAMP_UNIT_SECONDS);
  EXPECT_TRUE(fn != NULL);
  EXPECT_EQ(evictedId, 1);
}


static std::vector<uint32_t> evictedIds;
static void flowCbMultiple(pfwl_flow_info_t* flow_info){
  evictedIds.push_back(flow_info->id);
}

TEST(FlowTable, MaxFlowsEvictionMultiple) {
  pfwl_flow_table_t* table = pfwl_flow_table_create(PFWL_DEFAULT_FLOW_TABLE_AVG_BUCKET_SIZE, PFWL_FLOWS_STRATEGY_EVICT, 1);
  pflw_flow_table_set_flow_termination_callback(table, flowCbMultiple);
  char protos[128];
  memset(protos, 0, sizeof(protos));
  uint32_t ts = 0;
  pfwl_dissection_info_t p;

  p = initPktInfo(0, PFWL_DIRECTION_OUTBOUND);
  pfwl_flow_t* f1 = pfwl_flow_table_find_or_create_flow(table, &p, protos, 0, ts, 0, PFWL_TIMESTAMP_UNIT_SECONDS);
  EXPECT_TRUE(f1 != NULL);
 
  for(size_t i = 1; i < PFWL_DEFAULT_FLOW_TABLE_AVG_BUCKET_SIZE * 2; i++){
    ++ts;
    p = initPktInfo(i, PFWL_DIRECTION_OUTBOUND);
    pfwl_flow_t* fi = pfwl_flow_table_find_or_create_flow(table, &p, protos, 0, ts, 0, PFWL_TIMESTAMP_UNIT_SECONDS);
    EXPECT_TRUE(fi != NULL);
  }
  
  EXPECT_EQ(evictedIds.size(), PFWL_DEFAULT_FLOW_TABLE_AVG_BUCKET_SIZE);
  for(size_t i = 0; i < PFWL_DEFAULT_FLOW_TABLE_AVG_BUCKET_SIZE; i++){
    EXPECT_EQ(evictedIds[i], i);
  }
}