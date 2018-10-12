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

#if 0  // Suspended for the moment
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

pfwl_status_t mc_pfwl_parse_L4_header(
    pfwl_state_t* state, const unsigned char* pkt, size_t length,
    uint32_t timestamp, int tid, pfwl_dissection_info_t* dissection_info,
    pfwl_flow_info_private_t** flow_info_private) {
  uint8_t syn = 0;
  switch (dissection_info->l4.protocol) {
    case IPPROTO_TCP: {
      struct tcphdr* tcp = (struct tcphdr*)pkt;
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
      struct udphdr* udp = (struct udphdr*)pkt;
#ifdef PFWL_ENABLE_L4_TRUNCATION_PROTECTION
      if (unlikely(sizeof(struct udphdr) > length ||
                   ntohs(udp->len) > length)) {
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
  pfwl_flow_t* flow = pfwl_flow_table_find_or_create_flow(
      state->flow_table, dissection_info, state->protocols_to_inspect,
      state->tcp_reordering_enabled, timestamp, syn);
  if (unlikely(flow == NULL)) {
    return PFWL_ERROR_MAX_FLOWS;
  }

  *flow_info_private = &flow->info_private;

  ++flow->info.num_packets[dissection_info->l4.direction];
  flow->info.num_bytes[dissection_info->l4.direction] +=
      length + dissection_info->l3.length;

  if (flow->info_private.last_rebuilt_tcp_data) {
    free((void*)flow->info_private.last_rebuilt_tcp_data);
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

      if (seg.status == PFWL_TCP_REORDERING_STATUS_OUT_OF_ORDER) {
        return PFWL_STATUS_TCP_OUT_OF_ORDER;
      } else if (seg.status == PFWL_TCP_REORDERING_STATUS_REBUILT) {
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

pfwl_status_t pfwl_dissect_L4(pfwl_state_t* state, const unsigned char* pkt,
                              size_t length, uint32_t current_time,
                              pfwl_dissection_info_t* dissection_info,
                              pfwl_flow_info_private_t** flow_info_private) {
  /**
   * We can pass any thread id, indeed in this case we don't
   * need lock synchronization.
   **/
  return mc_pfwl_parse_L4_header(state, pkt, length, current_time, 0,
                                 dissection_info, flow_info_private);
}

pfwl_status_t pfwl_dissect_from_L4(pfwl_state_t* state,
                                   const unsigned char* pkt, size_t length,
                                   uint32_t timestamp,
                                   pfwl_dissection_info_t* dissection_info) {
  pfwl_status_t status;
  pfwl_flow_info_private_t* flow_info_private;
  status = pfwl_dissect_L4(state, pkt, length, timestamp, dissection_info,
                           &flow_info_private);

  if (unlikely(status < 0)) {
    if (dissection_info->l3.refrag_pkt) {
      free((unsigned char*)dissection_info->l3.refrag_pkt);
      dissection_info->l3.refrag_pkt = NULL;
      dissection_info->l3.refrag_pkt_len = 0;
    }
    return status;
  }

  dissection_info->flow_info = *flow_info_private->info_public;
  dissection_info->l7.protocol = flow_info_private->l7prot;

  // Store L3 fragmented data for later deletion
  if (flow_info_private->last_rebuilt_ip_fragments) {
    free((void*)flow_info_private->last_rebuilt_ip_fragments);
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
  const unsigned char* l7_pkt;

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
    pfwl_l7_skipping_info_t* sk = NULL;
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
