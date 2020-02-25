/*
 * peafowl_l4_parsing.c
 *
 * Created on: 19/09/2012
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
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
#include <peafowl/config.h>
#include <peafowl/flow_table.h>
#include <peafowl/hash_functions.h>
#include <peafowl/inspectors/inspectors.h>
#include <peafowl/ipv4_reassembly.h>
#include <peafowl/ipv6_reassembly.h>
#include <peafowl/peafowl.h>
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

typedef struct pfwl_l7_skipping_info_key {
  u_int16_t port;
  u_int8_t l4prot;
} pfwl_l7_skipping_info_key_t;

typedef struct pfwl_l7_skipping_info {
  pfwl_l7_skipping_info_key_t key;
  pfwl_protocol_l7_t protocol;
  UT_hash_handle hh; /* makes this structure hashable */
} pfwl_l7_skipping_info_t;

#if 0 // Suspended for the moment
/**
 * Skips the L7 parsing for packets traveling on some ports for some L4
 * protocol.
 * @param state A pointer to the state of the library.
 * @param l4prot The L4 protocol.
 * @param port The port.
 * @param id The protocol id that will be assigned to packets that matches with
 * this rule. If
 * id >= PFWL_PROTOCOL_UNKNOWN, it would be considered as a custom user protocol.
 * @return 0 if succeeded,
 *         1 otherwise.
 */
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
#endif


static void parse_tcp_opt_hdrs(pfwl_state_t *state, const unsigned char *pkt,
                               size_t length, pfwl_flow_t *flow, pfwl_direction_t direction){
  struct tcphdr *tcp = (struct tcphdr *) pkt;
  if(tcp->doff > 5 && state->stats_to_compute[PFWL_STAT_L4_TCP_WINDOW_SCALING]){
    const unsigned char* hdr = pkt + sizeof(struct tcphdr);
    while(hdr < pkt + length){
      uint8_t type = get_u8(hdr, 0);
      uint8_t length;
      if(type <= 1){
        // EOL (0) and NOP (1)
        length = 1;
      }else{
        length = get_u8(hdr, 1);
        if(type == 3){
          // Window Scaling
          if(length != 3){
            // Error
          }else{
            flow->info.statistics[PFWL_STAT_L4_TCP_WINDOW_SCALING][direction] = get_u8(hdr, 2);
          }
        }
      }
      hdr += length;
    }
  }
}

pfwl_status_t
mc_pfwl_parse_L4_header(pfwl_state_t *state, const unsigned char *pkt,
                        size_t length, double timestamp, int tid,
                        pfwl_dissection_info_t *dissection_info,
                        pfwl_flow_info_private_t **flow_info_private) {
  uint8_t syn = 0;
  switch (dissection_info->l4.protocol) {
  case IPPROTO_TCP: {
    struct tcphdr *tcp = (struct tcphdr *) pkt;
#ifdef PFWL_ENABLE_L4_TRUNCATION_PROTECTION
    if (unlikely(sizeof(struct tcphdr) > length || tcp->doff * 4 > length)) {
      return PFWL_ERROR_L4_PARSING;
    }
#endif
    dissection_info->l4.port_src = tcp->source;
    dissection_info->l4.port_dst = tcp->dest;
    dissection_info->l4.length = (tcp->doff * 4);
    syn = tcp->syn;    
  } break;
  case IPPROTO_UDP: {
    struct udphdr *udp = (struct udphdr *) pkt;
#ifdef PFWL_ENABLE_L4_TRUNCATION_PROTECTION
    if (unlikely(sizeof(struct udphdr) > length || ntohs(udp->len) > length)) {
      return PFWL_ERROR_L4_PARSING;
    }
#endif
    dissection_info->l4.port_src = udp->source;
    dissection_info->l4.port_dst = udp->dest;
    dissection_info->l4.length = sizeof(struct udphdr);
  } break;
  default: { dissection_info->l4.length = length; } break;
  }

  dissection_info->l4.payload_length = length - dissection_info->l4.length;
  pfwl_flow_t *flow = pfwl_flow_table_find_or_create_flow(
      state->flow_table, dissection_info, state->protocols_to_inspect,
      state->tcp_reordering_enabled, timestamp, syn, state->ts_unit);
  if (unlikely(flow == NULL)) {
    return PFWL_ERROR_MAX_FLOWS;
  }
  *flow_info_private = &flow->info_private;
  pfwl_direction_t direction = dissection_info->l4.direction;
  // Set flags statistics
  if(dissection_info->l4.protocol == IPPROTO_TCP){
    struct tcphdr *tcp = (struct tcphdr *) pkt;
    if(tcp->syn){
      flow->info.statistics[PFWL_STAT_L4_TCP_COUNT_SYN][direction]++;
    }
    if(tcp->fin){
      flow->info.statistics[PFWL_STAT_L4_TCP_COUNT_FIN][direction]++;
    }
    if(tcp->rst){
      flow->info.statistics[PFWL_STAT_L4_TCP_COUNT_RST][direction]++;
    }
    if(tcp->window == 0){
      flow->info.statistics[PFWL_STAT_L4_TCP_COUNT_ZERO_WINDOW][direction]++;
    }
    if(tcp->syn && tcp->ack){
      flow->info_private.synack_acknum = tcp->ack_seq;
      flow->info.statistics[PFWL_STAT_L4_TCP_RTT_SYN_ACK][1 - direction] = timestamp - flow->info.statistics[PFWL_STAT_TIMESTAMP_LAST][1 - direction];
    }
    if(tcp->seq == flow->info_private.synack_acknum &&
       direction == PFWL_DIRECTION_OUTBOUND){
      flow->info.statistics[PFWL_STAT_L4_TCP_RTT_SYN_ACK][1 - direction] = timestamp - flow->info.statistics[PFWL_STAT_TIMESTAMP_LAST][1 - direction];
    }
    parse_tcp_opt_hdrs(state, pkt, length, flow, direction);
  }

  // SPLT
  if(dissection_info->l4.payload_length){
    uint8_t id = flow->info.splt_stored_records[direction];
    double* ts_last_payload = &((*flow_info_private)->timestamp_last_payload[direction]);
    if(!(*ts_last_payload)){
      *ts_last_payload = timestamp;
    }
    if(id < PFWL_MAX_SPLT_LENGTH){
      flow->info.splt_times[id][direction] = timestamp - *ts_last_payload;
      flow->info.splt_lengths[id][direction] = dissection_info->l4.payload_length;
      ++flow->info.splt_stored_records[direction];
    }
    *ts_last_payload = timestamp;
  }

  ++flow->info.num_packets[direction];
  ++flow->info.statistics[PFWL_STAT_PACKETS][direction];
  flow->info.num_bytes[direction] +=
      length + dissection_info->l3.length;
  flow->info.statistics[PFWL_STAT_BYTES][direction] +=
      length + dissection_info->l3.length;

  if (flow->info_private.last_rebuilt_tcp_data) {
    free((void *) flow->info_private.last_rebuilt_tcp_data);
    flow->info_private.last_rebuilt_tcp_data = NULL;
  }

  pfwl_tcp_reordering_reordered_segment_t seg;
  seg.status = PFWL_TCP_REORDERING_STATUS_IN_ORDER;
  seg.data = NULL;
  seg.connection_terminated = 0;

  if (dissection_info->l4.protocol == IPPROTO_TCP &&
      state->active_protocols[0]) {
    if (flow->info_private.tcp_reordering_enabled) {
      seg = pfwl_reordering_tcp_track_connection(dissection_info,
                                                 &flow->info_private, pkt);

      if(seg.status == PFWL_TCP_REORDERING_STATUS_OUT_OF_ORDER) {
        return PFWL_STATUS_TCP_OUT_OF_ORDER;
      }else if(seg.status == PFWL_TCP_REORDERING_STATUS_RETRANSMISSION){
        flow->info.statistics[PFWL_STAT_L4_TCP_COUNT_RETRANSMISSIONS][direction]++;
        return PFWL_STATUS_TCP_OUT_OF_ORDER;
      }else if (seg.status == PFWL_TCP_REORDERING_STATUS_REBUILT) {
        dissection_info->l4.resegmented_pkt = seg.data;
        dissection_info->l4.resegmented_pkt_len = seg.data_length;
        flow->info_private.last_rebuilt_tcp_data = seg.data;
      }
    } else {
      if (pfwl_reordering_tcp_track_connection_light(pkt, dissection_info,
                                                     &flow->info_private)) {
        return PFWL_STATUS_TCP_CONNECTION_TERMINATED;
      }
    }
  }
  return PFWL_STATUS_OK;
}

pfwl_status_t pfwl_dissect_L4(pfwl_state_t *state, const unsigned char *pkt,
                              size_t length, double current_time,
                              pfwl_dissection_info_t *dissection_info,
                              pfwl_flow_info_private_t **flow_info_private) {
  /**
   * We can pass any thread id, indeed in this case we don't
   * need lock synchronization.
   **/
  return mc_pfwl_parse_L4_header(state, pkt, length, current_time, 0,
                                 dissection_info, flow_info_private);
}

pfwl_status_t pfwl_dissect_from_L4(pfwl_state_t *state,
                                   const unsigned char *pkt, size_t length,
                                   double timestamp,
                                   pfwl_dissection_info_t *dissection_info) {
  pfwl_status_t status;
  pfwl_flow_info_private_t *flow_info_private;
  status = pfwl_dissect_L4(state, pkt, length, timestamp, dissection_info,
                           &flow_info_private);

  if (unlikely(status < 0)) {
    if (dissection_info->l3.refrag_pkt) {
      free((unsigned char *) dissection_info->l3.refrag_pkt);
      dissection_info->l3.refrag_pkt = NULL;
      dissection_info->l3.refrag_pkt_len = 0;
    }
    return status;
  }

  dissection_info->flow_info = *flow_info_private->info_public;
  for(size_t i = 0; i < flow_info_private->info_public->protocols_l7_num; i++){
    dissection_info->l7.protocols[i] = flow_info_private->info_public->protocols_l7[i];
  }
  dissection_info->l7.protocols_num = flow_info_private->info_public->protocols_l7_num;
  dissection_info->l7.protocol = flow_info_private->info_public->protocols_l7[0];

  // Store L3 fragmented data for later deletion
  if (flow_info_private->last_rebuilt_ip_fragments) {
    free((void *) flow_info_private->last_rebuilt_ip_fragments);
    flow_info_private->last_rebuilt_ip_fragments = NULL;
  }
  if (dissection_info->l3.refrag_pkt) {
    flow_info_private->last_rebuilt_ip_fragments =
        dissection_info->l3.refrag_pkt;
  }

  if (status == PFWL_STATUS_TCP_OUT_OF_ORDER) {
    return status;
  } else if (status == PFWL_STATUS_TCP_CONNECTION_TERMINATED) {
    pfwl_flow_table_delete_flow_later(state->flow_table,
                                      flow_info_private->flow);
  }

  size_t l7_length;
  const unsigned char *l7_pkt;

  if (dissection_info->l4.resegmented_pkt_len) {
    l7_length = dissection_info->l4.resegmented_pkt_len;
    l7_pkt = dissection_info->l4.resegmented_pkt;
    dissection_info->l4.payload_length = l7_length;
  } else {
    l7_length = length - dissection_info->l4.length;
    l7_pkt = pkt + dissection_info->l4.length;
  }

  uint8_t skip_l7 = 0;
  if (HASH_COUNT(state->l7_skip)) {
    pfwl_l7_skipping_info_t *sk = NULL;
    pfwl_l7_skipping_info_key_t key;
    memset(&key, 0, sizeof(key));
    key.l4prot = dissection_info->l4.protocol;
    key.port = ntohs(dissection_info->l4.port_dst);
    HASH_FIND(hh, state->l7_skip, &key, sizeof(pfwl_l7_skipping_info_key_t),
              sk);
    if (sk) {
      skip_l7 = 1;
      dissection_info->l7.protocol = sk->protocol;
    } else {
      key.port = ntohs(dissection_info->l4.port_src);
      HASH_FIND(hh, state->l7_skip, &key, sizeof(pfwl_l7_skipping_info_key_t),
                sk);
      if (sk) {
        skip_l7 = 1;
        dissection_info->l7.protocol = sk->protocol;
      }
    }
  }

  if (l7_length && !skip_l7) {
    /**
     * We return the status of pfwl_stateful_get_app_protocol call,
     * without giving informations on status returned
     * by pfwl_parse_L3_L4_headers. Basically we return the status which
     * provides more informations.
     */
    status = pfwl_dissect_L7(state, l7_pkt, l7_length, dissection_info,
                             flow_info_private);
  }
  return status;
}

static const char* pfwl_l4_protocols_names[IPPROTO_MAX] = {
  [0 ... IPPROTO_MAX - 1] = "Unknown",
#ifdef IPPROTO_IP
  [IPPROTO_IP]      = "IP",
#endif
#ifdef IPPROTO_ICMP
  [IPPROTO_ICMP]    = "ICMP",
#endif
#ifdef IPPROTO_IGMP
  [IPPROTO_IGMP]    = "IGMP",
#endif
#ifdef IPPROTO_IPIP
  [IPPROTO_IPIP]    = "IPIP",
#endif
#ifdef IPPROTO_TCP
  [IPPROTO_TCP]     = "TCP",
#endif
#ifdef IPPROTO_EGP
  [IPPROTO_EGP]     = "EGP",
#endif
#ifdef IPPROTO_PUP
  [IPPROTO_PUP]     = "PUP",
#endif
#ifdef IPPROTO_UDP
  [IPPROTO_UDP]     = "UDP",
#endif
#ifdef IPPROTO_IDP
  [IPPROTO_IDP]     = "IDP",
#endif
#ifdef IPPROTO_TP
  [IPPROTO_TP]      = "TP",
#endif
#ifdef IPPROTO_DCCP
  [IPPROTO_DCCP]    = "DCCP",
#endif
#ifdef IPPROTO_IPV6
  [IPPROTO_IPV6]    = "IPV6",
#endif
#ifdef IPPROTO_RSVP
  [IPPROTO_RSVP]    = "RSVP",
#endif
#ifdef IPPROTO_GRE
  [IPPROTO_GRE]     = "GRE",
#endif
#ifdef IPPROTO_ESP
  [IPPROTO_ESP]     = "ESP",
#endif
#ifdef IPPROTO_AH
  [IPPROTO_AH]      = "AH",
#endif
  [58]              = "ICMPv6",
#ifdef IPPROTO_MTP
  [IPPROTO_MTP]     = "MTP",
#endif
#ifdef IPPROTO_BEETPH
  [IPPROTO_BEETPH]  = "BEETPH",
#endif
#ifdef IPPROTO_ENCAP
  [IPPROTO_ENCAP]   = "ENCAP",
#endif
#ifdef IPPROTO_PIM
  [IPPROTO_PIM]     = "PIM",
#endif
#ifdef IPPROTO_COMP
  [IPPROTO_COMP]    = "COMP",
#endif
#ifdef IPPROTO_SCTP
  [IPPROTO_SCTP]    = "SCTP",
#endif
#ifdef IPPROTO_UDPLITE
  [IPPROTO_UDPLITE] = "UDPLITE",
#endif
#ifdef IPPROTO_MPLS
  [IPPROTO_MPLS]    = "MPLS",
#endif
#ifdef IPPROTO_RAW
  [IPPROTO_RAW]     = "RAW"
#endif
};

const char *pfwl_get_L4_protocol_name(pfwl_protocol_l4_t protocol){
  if(protocol < IPPROTO_MAX){
    return pfwl_l4_protocols_names[protocol];
  }else{
    return "Unknown";
  }
}

pfwl_protocol_l4_t pfwl_get_L4_protocol_id(const char *const name){
  size_t i;
  for (i = 0; i < (size_t) IPPROTO_MAX; i++) {
    if (!strcasecmp(name, pfwl_l4_protocols_names[i])) {
      return (pfwl_protocol_l4_t) i;
    }
  }
  return 0;
}


const char **const pfwl_get_L4_protocols_names(){
  return pfwl_l4_protocols_names;
}
