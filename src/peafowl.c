/*
 * peafowl.c
 *
 * Created on: 19/09/2012
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * =========================================================================
 */

#include <peafowl/peafowl.h>
#include <peafowl/config.h>
#include <peafowl/flow_table.h>
#include <peafowl/hash_functions.h>
#include <peafowl/inspectors/inspectors.h>
#include <peafowl/ipv4_reassembly.h>
#include <peafowl/ipv6_reassembly.h>
#include <peafowl/tcp_stream_management.h>
#include <peafowl/utils.h>

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define debug_print(fmt, ...)                         \
  do {                                                \
    if (PFWL_DEBUG) fprintf(stderr, fmt, __VA_ARGS__); \
  } while (0)

typedef struct pfwl_l7_skipping_info_key {
  u_int16_t port;
  u_int8_t l4prot;
} pfwl_l7_skipping_info_key_t;

typedef struct pfwl_l7_skipping_info {
  pfwl_l7_skipping_info_key_t key;
  pfwl_protocol_l7_t protocol;
  UT_hash_handle hh; /* makes this structure hashable */
} pfwl_l7_skipping_info_t;


uint8_t pfwl_set_expected_flows(pfwl_state_t *state, uint32_t flows, uint8_t strict){
  if(state->flow_table){
    pfwl_flow_table_delete(state->flow_table);
    state->flow_table = pfwl_flow_table_create(flows, strict, 1);
  }

  return 0;
}

pfwl_state_t* pfwl_init_stateful_num_partitions(uint32_t expected_flows,
                                                uint8_t strict,
                                                uint16_t num_table_partitions) {
  pfwl_state_t* state =
      (pfwl_state_t*)malloc(sizeof(pfwl_state_t));

  assert(state);

  bzero(state, sizeof(pfwl_state_t));

#if PFWL_FLOW_TABLE_USE_MEMORY_POOL
  state->db4 = pfwl_flow_table_create_v4(
      size_v4, max_active_v4_flows, num_table_partitions,
      PFWL_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v4);
  state->db6 = pfwl_flow_table_create_v6(
      size_v6, max_active_v6_flows, num_table_partitions,
      PFWL_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v6);
#else
  state->flow_table = pfwl_flow_table_create(expected_flows, strict, num_table_partitions);
#endif
  pfwl_set_max_trials(state, PFWL_DEFAULT_MAX_TRIALS_PER_FLOW);
  pfwl_inspect_all(state);

  pfwl_ipv4_fragmentation_enable(state,
                                PFWL_IPv4_FRAGMENTATION_DEFAULT_TABLE_SIZE);
  pfwl_ipv6_fragmentation_enable(state,
                                PFWL_IPv6_FRAGMENTATION_DEFAULT_TABLE_SIZE);

  pfwl_tcp_reordering_enable(state);

  state->l7_skip = NULL;

  for(size_t i = 0; i < PFWL_NUM_PROTOCOLS; i++){
    memset(state->fields_to_extract, 0, sizeof(state->fields_to_extract));
    memset(state->fields_to_extract_num, 0, sizeof(state->fields_to_extract_num));
  }

  return state;
}

pfwl_state_t* pfwl_init(){
  return pfwl_init_stateful_num_partitions(PFWL_DEFAULT_EXPECTED_FLOWS, 0, 1);
}

pfwl_state_t* pfwl_init_stateless() {
  return pfwl_init();
}

uint8_t pfwl_set_max_trials(pfwl_state_t* state, uint16_t max_trials) {
  state->max_trials = max_trials;
  return 0;
}

uint8_t pfwl_ipv4_fragmentation_enable(pfwl_state_t* state,
                                      uint16_t table_size) {
  if (state) {
    state->ipv4_frag_state =
        pfwl_reordering_enable_ipv4_fragmentation(table_size);
    if (state->ipv4_frag_state) {
      return 0;
    } else {
      return 1;
    }
  } else {
    return 1;
  }
}

uint8_t pfwl_ipv6_fragmentation_enable(pfwl_state_t* state,
                                      uint16_t table_size) {
  if (likely(state)) {
    state->ipv6_frag_state =
        pfwl_reordering_enable_ipv6_fragmentation(table_size);
    if (state->ipv6_frag_state) {
      return 0;
    } else {
      return 1;
    }
  } else {
    return 1;
  }
}

uint8_t pfwl_ipv4_fragmentation_set_per_host_memory_limit(
    pfwl_state_t* state, uint32_t per_host_memory_limit) {
  if (likely(state && state->ipv4_frag_state)) {
    pfwl_reordering_ipv4_fragmentation_set_per_host_memory_limit(
        state->ipv4_frag_state, per_host_memory_limit);
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_ipv6_fragmentation_set_per_host_memory_limit(
    pfwl_state_t* state, uint32_t per_host_memory_limit) {
  if (likely(state && state->ipv6_frag_state)) {
    pfwl_reordering_ipv6_fragmentation_set_per_host_memory_limit(
        state->ipv6_frag_state, per_host_memory_limit);
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_ipv4_fragmentation_set_total_memory_limit(
    pfwl_state_t* state, uint32_t total_memory_limit) {
  if (likely(state && state->ipv4_frag_state)) {
    pfwl_reordering_ipv4_fragmentation_set_total_memory_limit(
        state->ipv4_frag_state, total_memory_limit);
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_ipv6_fragmentation_set_total_memory_limit(
    pfwl_state_t* state, uint32_t total_memory_limit) {
  if (likely(state && state->ipv6_frag_state)) {
    pfwl_reordering_ipv6_fragmentation_set_total_memory_limit(
        state->ipv6_frag_state, total_memory_limit);
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_ipv4_fragmentation_set_reassembly_timeout(
    pfwl_state_t* state, uint8_t timeout_seconds) {
  if (likely(state && state->ipv4_frag_state)) {
    pfwl_reordering_ipv4_fragmentation_set_reassembly_timeout(
        state->ipv4_frag_state, timeout_seconds);
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_ipv6_fragmentation_set_reassembly_timeout(
    pfwl_state_t* state, uint8_t timeout_seconds) {
  if (likely(state && state->ipv6_frag_state)) {
    pfwl_reordering_ipv6_fragmentation_set_reassembly_timeout(
        state->ipv6_frag_state, timeout_seconds);
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_ipv4_fragmentation_disable(pfwl_state_t* state) {
  if (likely(state && state->ipv4_frag_state)) {
    pfwl_reordering_disable_ipv4_fragmentation(state->ipv4_frag_state);
    state->ipv4_frag_state = NULL;
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_ipv6_fragmentation_disable(pfwl_state_t* state) {
  if (likely(state && state->ipv6_frag_state)) {
    pfwl_reordering_disable_ipv6_fragmentation(state->ipv6_frag_state);
    state->ipv6_frag_state = NULL;
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_tcp_reordering_enable(pfwl_state_t* state) {
  if (likely(state)) {
    state->tcp_reordering_enabled = 1;
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_tcp_reordering_disable(pfwl_state_t* state) {
  if (likely(state)) {
    state->tcp_reordering_enabled = 0;
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_enable_protocol(pfwl_state_t* state,
                             pfwl_protocol_l7_t protocol) {
  if (protocol < PFWL_NUM_PROTOCOLS) {
    // Increment counter only if it was not set, otherwise
    // calling twice enable_protocol on the same protocol
    // would lead to a wrong number of active protocols
    if(!BITTEST(state->protocols_to_inspect, protocol)){
      ++state->active_protocols;
    }
    BITSET(state->protocols_to_inspect, protocol);    
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_disable_protocol(pfwl_state_t* state,
                             pfwl_protocol_l7_t protocol) {
  if (protocol < PFWL_NUM_PROTOCOLS) {
    // Decrement counter only if it was set, otherwise
    // calling twice disable_protocol on the same protocol
    // would lead to a wrong number of active protocols
    if(BITTEST(state->protocols_to_inspect, protocol)){
      --state->active_protocols;
    }
    BITCLEAR(state->protocols_to_inspect, protocol);
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_inspect_all(pfwl_state_t* state) {
  unsigned char nonzero = ~0;
  memset(state->protocols_to_inspect, nonzero, BITNSLOTS(PFWL_NUM_PROTOCOLS));
  state->active_protocols = PFWL_NUM_PROTOCOLS;
  return 0;
}

uint8_t pfwl_inspect_nothing(pfwl_state_t* state) {
  bzero(state->protocols_to_inspect, BITNSLOTS(PFWL_NUM_PROTOCOLS));
  state->active_protocols = 0;
  return 0;
}

uint8_t pfwl_skip_L7_parsing_by_port(pfwl_state_t* state, uint8_t l4prot,
                                    uint16_t port, pfwl_protocol_l7_t id) {
  pfwl_l7_skipping_info_t* skinfo = malloc(sizeof(pfwl_l7_skipping_info_t));
  memset(skinfo, 0, sizeof(pfwl_l7_skipping_info_t));
  skinfo->key.l4prot = l4prot;
  skinfo->key.port = port;
  skinfo->protocol = id;
  HASH_ADD(hh, state->l7_skip, key, sizeof(skinfo->key), skinfo);
  return 0;
}

void pfwl_terminate(pfwl_state_t* state) {
  if (likely(state)) {
    pfwl_ipv4_fragmentation_disable(state);
    pfwl_ipv6_fragmentation_disable(state);
    pfwl_tcp_reordering_disable(state);

    pfwl_flow_table_delete(state->flow_table);
    free(state);
  }
}


pfwl_dissection_info_t pfwl_dissect_from_L2(pfwl_state_t* state, const unsigned char* pkt,
                                            uint32_t length, uint32_t timestamp,
                                            int datalink_type){
  pfwl_dissection_info_t r;
  memset(&r, 0, sizeof(r));
  pfwl_parse_L2(pkt, datalink_type, &r);
  pfwl_dissect_from_L3(state, pkt + r.offset_l3, length - r.offset_l3, timestamp, &r);
  return r;
}

void pfwl_dissect_from_L3(pfwl_state_t* state,
                          const unsigned char* pkt,
                          uint32_t length,
                          uint32_t timestamp,
                          pfwl_dissection_info_t* r) {
  pfwl_parse_L3_L4(state, pkt, length, timestamp, r);
  if (unlikely(r->status == PFWL_STATUS_IP_FRAGMENT || r->status < 0)) {
    return;
  }

  uint8_t skip_l7 = 0;
  uint16_t srcport = ntohs(r->port_src);
  uint16_t dstport = ntohs(r->port_dst);
  pfwl_l7_skipping_info_t* sk = NULL;
  pfwl_l7_skipping_info_key_t key;
  memset(&key, 0, sizeof(key));
  key.l4prot = r->protocol_l4;
  key.port = dstport;
  HASH_FIND(hh, state->l7_skip, &key, sizeof(pfwl_l7_skipping_info_key_t), sk);
  if (sk) {
    skip_l7 = 1;
    r->protocol_l7 = sk->protocol;
  } else {
    key.port = srcport;
    HASH_FIND(hh, state->l7_skip, &key, sizeof(pfwl_l7_skipping_info_key_t),
              sk);
    if (sk) {
      skip_l7 = 1;
      r->protocol_l7 = sk->protocol;
    }
  }

  if (!skip_l7) {
    if (r->protocol_l4 != IPPROTO_TCP && r->protocol_l4 != IPPROTO_UDP) {
      return;
    }

    /**
     * We return the status of pfwl_stateful_get_app_protocol call,
     * without giving informations on status returned
     * by pfwl_parse_L3_L4_headers. Basically we return the status which
     * provides more informations.
     */
    pfwl_parse_L7(state, r);
  }
  return;
}

uint8_t pfwl_set_protocol_accuracy(pfwl_state_t *state,
                                  pfwl_protocol_l7_t protocol,
                                  pfwl_inspector_accuracy_t accuracy) {
  if (state) {
    state->inspectors_accuracy[protocol] = accuracy;
    return 0;
  } else {
    return 1;
  }
}

const char* const pfwl_get_error_msg(int8_t error_code) {
  switch (error_code) {
    case PFWL_ERROR_WRONG_IPVERSION:
      return "ERROR: The packet is neither IPv4 nor IPv6.";
    case PFWL_ERROR_IPSEC_NOTSUPPORTED:
      return "ERROR: The packet is encrypted using IPSEC. "
             "IPSEC is not supported.";
    case PFWL_ERROR_L3_TRUNCATED_PACKET:
      return "ERROR: The L3 packet is truncated or corrupted.";
    case PFWL_ERROR_L4_TRUNCATED_PACKET:
      return "ERROR: The L4 packet is truncated or corrupted.";
    case PFWL_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED:
      return "ERROR: The transport protocol is not supported.";
    case PFWL_ERROR_MAX_FLOWS:
      return "ERROR: The maximum number of active flows has been"
             " reached. Please increase it when initializing the libray";
    default:
      return "ERROR: Not existing error code.";
  }
}

const char* const pfwl_get_status_msg(int8_t status_code) {
  switch (status_code) {
    case PFWL_STATUS_OK:
      return "STATUS: Everything is ok.";
    case PFWL_STATUS_IP_FRAGMENT:
      return "STATUS: The received IP datagram is a fragment of a "
             " bigger datagram.";
    case PFWL_STATUS_IP_LAST_FRAGMENT:
      return "STATUS: The received IP datagram is the last fragment"
             " of a bigger datagram. The original datagram has been"
             " recomposed.";
    case PFWL_STATUS_TCP_OUT_OF_ORDER:
      return "STATUS: The received TCP segment is out of order in "
             " its stream. It will be buffered waiting for in order"
             " segments.";
    case PFWL_STATUS_TCP_CONNECTION_TERMINATED:
      return "STATUS: The TCP connection is terminated.";
    default:
      return "STATUS: Not existing status code.";
  }
}

uint8_t pfwl_set_flow_cleaner_callback(pfwl_state_t* state, pfwl_flow_cleaner_callback_t* cleaner) {
  pflw_flow_table_set_flow_cleaner_callback(state->flow_table, cleaner);
  return 0;
}

static pfwl_protocol_l7_t pfwl_get_protocol_from_field(pfwl_field_id_t field){
  if(field >= PFWL_FIELDS_SIP_FIRST && field < PFWL_FIELDS_SIP_LAST){
    return PFWL_PROTOCOL_SIP;
  }else if(field >= PFWL_FIELDS_DNS_FIRST && field < PFWL_FIELDS_DNS_LAST){
    return PFWL_PROTOCOL_DNS;
  }else if(field >= PFWL_FIELDS_SSL_FIRST && field < PFWL_FIELDS_SSL_LAST){
    return PFWL_PROTOCOL_SSL;
  }else if(field >= PFWL_FIELDS_HTTP_FIRST && field < PFWL_FIELDS_HTTP_LAST){
    return PFWL_PROTOCOL_HTTP;
  }else{
    return PFWL_NUM_PROTOCOLS;
  }
}

uint8_t pfwl_protocol_field_add(pfwl_state_t* state, pfwl_field_id_t field){
  if(state){
    if(!state->fields_to_extract[field]){
      pfwl_protocol_l7_t protocol = pfwl_get_protocol_from_field(field);
      if(protocol == PFWL_NUM_PROTOCOLS){
        return 0;
      }
      ++state->fields_to_extract_num[protocol];
      pfwl_set_protocol_accuracy(state, protocol, PFWL_INSPECTOR_ACCURACY_HIGH);  // TODO: mmm, the problem is that we do not set back the original accuracy when doing field_remove
    }
    state->fields_to_extract[field] = 1;
    return 0;
  }else{
    return 1;
  }
}

uint8_t pfwl_protocol_field_remove(pfwl_state_t* state, pfwl_field_id_t field){
  if(state){
    if(state->fields_to_extract[field]){
      pfwl_protocol_l7_t protocol = pfwl_get_protocol_from_field(field);
      if(protocol == PFWL_NUM_PROTOCOLS){
        return 0;
      }
      --state->fields_to_extract_num[protocol];
    }
    state->fields_to_extract[field] = 0;
    return 0;
  }else{
    return 1;
  }
}

uint8_t pfwl_protocol_field_required(pfwl_state_t* state, pfwl_field_id_t field){
  if(state){
    return state->fields_to_extract[field];
  }else{
    return 0;
  }
}

void pfwl_init_flow_info(pfwl_state_t* state,
                         pfwl_flow_info_t* flow_info){
  pfwl_init_flow_info_internal(flow_info,
                               state->protocols_to_inspect,
                               state->tcp_reordering_enabled);
}
