/*
 * peafowl_l4_parsing.c
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


void mc_pfwl_parse_L4_header(pfwl_state_t* state,
                             const unsigned char* pkt,
                             size_t length,
                             uint32_t timestamp, int tid,
                             pfwl_dissection_info_t* dissection_info){
  switch(dissection_info->l4.protocol){
  case IPPROTO_TCP:{
    struct tcphdr* tcp = (struct tcphdr*) pkt;
#ifdef PFWL_ENABLE_L4_TRUNCATION_PROTECTION
    if (unlikely(sizeof(struct tcphdr) > length || tcp->doff * 4 > length)) {
      dissection_info->status = PFWL_ERROR_L4_PARSING;
      return;
    }
#endif
    dissection_info->l4.port_src = tcp->source;
    dissection_info->l4.port_dst = tcp->dest;
    dissection_info->l4.length = (tcp->doff * 4);
  }break;
  case IPPROTO_UDP:{
    struct udphdr* udp = (struct udphdr*) pkt;
#ifdef PFWL_ENABLE_L4_TRUNCATION_PROTECTION
    if (unlikely(sizeof(struct udphdr) > length || ntohs(udp->len) > length)) {
      dissection_info->status = PFWL_ERROR_L4_PARSING;
      return;
    }
#endif
    dissection_info->l4.port_src = udp->source;
    dissection_info->l4.port_dst = udp->dest;
    dissection_info->l4.length = sizeof(struct udphdr);
  }break;
  default:{
    return;
  }break;
  }
}


pfwl_flow_t* mc_pfwl_parse_L4_header_internal(pfwl_state_t* state,
                             const unsigned char* pkt,
                             size_t length,
                             uint32_t timestamp, int tid,
                             pfwl_dissection_info_t* dissection_info){
  mc_pfwl_parse_L4_header(state, pkt, length, timestamp, tid, dissection_info);
  dissection_info->l7.length = length - dissection_info->l4.length;
  pfwl_flow_t* flow = pfwl_flow_table_find_or_create_flow(state->flow_table, dissection_info,
                                             state->protocols_to_inspect, state->tcp_reordering_enabled,
                                             timestamp);
  if (unlikely(flow == NULL)) {
    dissection_info->status = PFWL_ERROR_MAX_FLOWS;
    return flow;
  }

  pfwl_tcp_reordering_reordered_segment_t seg;
  seg.status = PFWL_TCP_REORDERING_STATUS_IN_ORDER;
  seg.data = NULL;
  seg.connection_terminated = 0;

  if (dissection_info->l4.protocol == IPPROTO_TCP) { // TODO Check if there are TCP active protocols
    if (flow->info_private.tcp_reordering_enabled) {
      seg = pfwl_reordering_tcp_track_connection(dissection_info, &flow->info_private);

      if (seg.status == PFWL_TCP_REORDERING_STATUS_OUT_OF_ORDER) {
        dissection_info->status = PFWL_STATUS_TCP_OUT_OF_ORDER;
        return flow;
      } else if (seg.status == PFWL_TCP_REORDERING_STATUS_REBUILT) {
        dissection_info->l4.resegmented_pkt = seg.data;
        dissection_info->l4.resegmented_pkt_len = seg.data_length;
        if(flow->info_private.last_rebuilt_tcp_data){
          free((void*) flow->info_private.last_rebuilt_tcp_data);
        }
        flow->info_private.last_rebuilt_tcp_data = seg.data;
      }
    } else {
      if (pfwl_reordering_tcp_track_connection_light(dissection_info, &flow->info_private)){
        dissection_info->status = PFWL_STATUS_TCP_CONNECTION_TERMINATED;
      }
    }
  }

  return flow;
}


void pfwl_parse_L4(pfwl_state_t* state,
                   const unsigned char* pkt,
                   size_t length,
                   uint32_t current_time,
                   pfwl_dissection_info_t* dissection_info) {
  /**
   * We can pass any thread id, indeed in this case we don't
   * need lock synchronization.
   **/
  mc_pfwl_parse_L4_header(state, pkt, length, current_time, 0, dissection_info);
}


pfwl_flow_t* pfwl_parse_L4_internal(pfwl_state_t* state,
                   const unsigned char* pkt,
                   size_t length,
                   uint32_t current_time,
                   pfwl_dissection_info_t* dissection_info) {
  /**
   * We can pass any thread id, indeed in this case we don't
   * need lock synchronization.
   **/
  return mc_pfwl_parse_L4_header_internal(state, pkt, length, current_time, 0, dissection_info);
}
