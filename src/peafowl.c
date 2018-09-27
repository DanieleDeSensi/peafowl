/*
 * peafowl.c
 *
 * Created on: 19/09/2012
 * =========================================================================
 *  Copyright (C) 2012-2018, Daniele De Sensi (d.desensi.software@gmail.com)
 *
 *  This file is part of Peafowl.
 *
 *  Peafowl is free software: you can redistribute it and/or
 *  modify it under the terms of the Lesser GNU General Public
 *  License as published by the Free Software Foundation, either
 *  version 3 of the License, or (at your option) any later version.

 *  Peafowl is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  Lesser GNU General Public License for more details.
 *
 *  You should have received a copy of the Lesser GNU General Public
 *  License along with Peafowl.
 *  If not, see <http://www.gnu.org/licenses/>.
 *
 * =========================================================================
 */

#include <peafowl/peafowl.h>
#include <peafowl/config.h>
#include <peafowl/flow_table.h>
#include <peafowl/hash_functions.h>
#include <peafowl/inspectors/inspectors.h>
#include <peafowl/inspectors/structures.h>
#include <peafowl/ipv4_reassembly.h>
#include <peafowl/ipv6_reassembly.h>
#include <peafowl/tcp_stream_management.h>
#include <peafowl/utils.h>

#include <arpa/inet.h>
#include <assert.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#ifdef WITH_PROMETHEUS
#include "prometheus.h"
#endif

#define debug_print(fmt, ...)                         \
  do {                                                \
    if (PFWL_DEBUG) fprintf(stderr, fmt, __VA_ARGS__); \
  } while (0)

static const pfwl_protocol_l7 const
    pfwl_well_known_ports_association_tcp[PFWL_MAX_UINT_16 + 1] =
        {[0 ... PFWL_MAX_UINT_16] = PFWL_PROTOCOL_UNKNOWN,
         [port_dns] = PFWL_PROTOCOL_DNS,
         [port_http] = PFWL_PROTOCOL_HTTP,
         [port_bgp] = PFWL_PROTOCOL_BGP,
         [port_smtp_1] = PFWL_PROTOCOL_SMTP,
         [port_smtp_2] = PFWL_PROTOCOL_SMTP,
         [port_smtp_ssl] = PFWL_PROTOCOL_SMTP,
         [port_pop3] = PFWL_PROTOCOL_POP3,
         [port_pop3_ssl] = PFWL_PROTOCOL_POP3,
         [port_imap] = PFWL_PROTOCOL_IMAP,
         [port_imap_ssl] = PFWL_PROTOCOL_IMAP,
         [port_ssl] = PFWL_PROTOCOL_SSL,
         [port_hangout_19305] = PFWL_PROTOCOL_HANGOUT,
         [port_hangout_19306] = PFWL_PROTOCOL_HANGOUT,
         [port_hangout_19307] = PFWL_PROTOCOL_HANGOUT,
         [port_hangout_19308] = PFWL_PROTOCOL_HANGOUT,
         [port_hangout_19309] = PFWL_PROTOCOL_HANGOUT,
         [port_ssh] = PFWL_PROTOCOL_SSH,};

static const pfwl_protocol_l7 const
    pfwl_well_known_ports_association_udp[PFWL_MAX_UINT_16 + 1] =
        {[0 ... PFWL_MAX_UINT_16] = PFWL_PROTOCOL_UNKNOWN,
         [port_dns] = PFWL_PROTOCOL_DNS,
         [port_mdns] = PFWL_PROTOCOL_MDNS,
         [port_dhcp_1] = PFWL_PROTOCOL_DHCP,
         [port_dhcp_2] = PFWL_PROTOCOL_DHCP,
         [port_dhcpv6_1] = PFWL_PROTOCOL_DHCPv6,
         [port_dhcpv6_2] = PFWL_PROTOCOL_DHCPv6,
         [port_sip] = PFWL_PROTOCOL_SIP,
         [port_ntp] = PFWL_PROTOCOL_NTP,
         [port_hangout_19302] = PFWL_PROTOCOL_HANGOUT,
         [port_hangout_19303] = PFWL_PROTOCOL_HANGOUT,
         [port_hangout_19304] = PFWL_PROTOCOL_HANGOUT,
         [port_hangout_19305] = PFWL_PROTOCOL_HANGOUT,
         [port_hangout_19306] = PFWL_PROTOCOL_HANGOUT,
         [port_hangout_19307] = PFWL_PROTOCOL_HANGOUT,
         [port_hangout_19308] = PFWL_PROTOCOL_HANGOUT,
         [port_hangout_19309] = PFWL_PROTOCOL_HANGOUT,
         [port_dropbox] = PFWL_PROTOCOL_DROPBOX,
         [port_spotify] = PFWL_PROTOCOL_SPOTIFY,};

typedef struct{
  const char* name;
  pfwl_inspector_callback dissector;
  pfwl_get_extracted_fields_callback get_extracted_fields;
  int extracted_fields_num;
}pfwl_protocol_descriptor_t;

static const pfwl_protocol_descriptor_t const protocols_descriptors[PFWL_NUM_PROTOCOLS] =
  {
    [PFWL_PROTOCOL_DHCP]     = {"DHCP"    , check_dhcp    , NULL, 0},
    [PFWL_PROTOCOL_DHCPv6]   = {"DHCPv6"  , check_dhcpv6  , NULL, 0},
    [PFWL_PROTOCOL_DNS]      = {"DNS"     , check_dns     , get_extracted_fields_dns, PFWL_FIELDS_DNS_NUM},
    [PFWL_PROTOCOL_MDNS]     = {"MDNS"    , check_mdns    , NULL, 0},
    [PFWL_PROTOCOL_SIP]      = {"SIP"     , check_sip     , get_extracted_fields_sip, PFWL_FIELDS_SIP_NUM},
    [PFWL_PROTOCOL_RTP]      = {"RTP"     , check_rtp     , NULL, 0},
    [PFWL_PROTOCOL_SSH]      = {"SSH"     , check_ssh     , NULL, 0},
    [PFWL_PROTOCOL_SKYPE]    = {"Skype"   , check_skype   , NULL, 0},
    [PFWL_PROTOCOL_NTP]      = {"NTP"     , check_ntp     , NULL, 0},
    [PFWL_PROTOCOL_BGP]      = {"BGP"     , check_bgp     , NULL, 0},
    [PFWL_PROTOCOL_HTTP]     = {"HTTP"    , check_http    , NULL, 0},
    [PFWL_PROTOCOL_SMTP]     = {"SMTP"    , check_smtp    , NULL, 0},
    [PFWL_PROTOCOL_POP3]     = {"POP3"    , check_pop3    , NULL, 0},
    [PFWL_PROTOCOL_IMAP]     = {"IMAP"    , check_imap    , NULL, 0},
    [PFWL_PROTOCOL_SSL]      = {"SSL"     , check_ssl     , NULL, 0},
    [PFWL_PROTOCOL_HANGOUT]  = {"Hangout" , check_hangout , NULL, 0},
    [PFWL_PROTOCOL_WHATSAPP] = {"WhatsApp", check_whatsapp, NULL, 0},
    [PFWL_PROTOCOL_TELEGRAM] = {"Telegram", check_telegram, NULL, 0},
    [PFWL_PROTOCOL_DROPBOX]  = {"Dropbox" , check_dropbox , NULL, 0},
    [PFWL_PROTOCOL_SPOTIFY]  = {"Spotify" , check_spotify , NULL, 0},
};

static const pfwl_inspector_callback const callbacks_manager[PFWL_NUM_PROTOCOLS] = {
    [PFWL_PROTOCOL_HTTP] = invoke_callbacks_http,
    [PFWL_PROTOCOL_SSL] = invoke_callbacks_ssl,
};

typedef struct pfwl_l7_skipping_infos_key {
  u_int16_t port;
  u_int8_t l4prot;
} pfwl_l7_skipping_infos_key_t;

typedef struct pfwl_l7_skipping_infos {
  pfwl_l7_skipping_infos_key_t key;
  pfwl_protocol_l7 protocol;
  UT_hash_handle hh; /* makes this structure hashable */
} pfwl_l7_skipping_infos_t;


pfwl_state_t* pfwl_init_stateful_num_partitions(
    uint32_t size_v4, uint32_t size_v6, uint32_t max_active_v4_flows,
    uint32_t max_active_v6_flows, uint16_t num_table_partitions) {
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
  state->db4 = pfwl_flow_table_create_v4(size_v4, max_active_v4_flows,
                                        num_table_partitions);
  state->db6 = pfwl_flow_table_create_v6(size_v6, max_active_v6_flows,
                                        num_table_partitions);
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
    size_t num_callbacks = protocols_descriptors[i].extracted_fields_num;
    state->fields_extraction[i].fields = (uint8_t*) malloc(sizeof(uint8_t)*num_callbacks);
    state->fields_extraction[i].fields_num = 0;
    for(size_t j = 0; j < num_callbacks; j++){
      state->fields_extraction[i].fields[j] = 0;
    }
  }

  return state;
}

pfwl_state_t* pfwl_init_stateful(uint32_t size_v4, uint32_t size_v6,
				 uint32_t max_active_v4_flows,
				 uint32_t max_active_v6_flows) {
  return pfwl_init_stateful_num_partitions(size_v4, size_v6, max_active_v4_flows,
					   max_active_v6_flows, 1);
}


pfwl_state_t* pfwl_init_stateless(void) {
  return pfwl_init_stateful(0, 0, 0, 0);
}


uint8_t pfwl_set_max_trials(pfwl_state_t* state, uint16_t max_trials) {
  state->max_trials = max_trials;
  return PFWL_STATE_UPDATE_SUCCESS;
}


uint8_t pfwl_ipv4_fragmentation_enable(pfwl_state_t* state,
				       uint16_t table_size) {
  if (likely(state)) {
    state->ipv4_frag_state =
        pfwl_reordering_enable_ipv4_fragmentation(table_size);
    if (state->ipv4_frag_state)
      return PFWL_STATE_UPDATE_SUCCESS;
    else
      return PFWL_STATE_UPDATE_FAILURE;
  } else
    return PFWL_STATE_UPDATE_FAILURE;
}


uint8_t pfwl_ipv6_fragmentation_enable(pfwl_state_t* state,
				       uint16_t table_size) {
  if (likely(state)) {
    state->ipv6_frag_state =
        pfwl_reordering_enable_ipv6_fragmentation(table_size);
    if (state->ipv6_frag_state)
      return PFWL_STATE_UPDATE_SUCCESS;
    else
      return PFWL_STATE_UPDATE_FAILURE;
  } else {
    return PFWL_STATE_UPDATE_FAILURE;
  }
}


uint8_t pfwl_ipv4_fragmentation_set_per_host_memory_limit(pfwl_state_t* state,
							  uint32_t per_host_memory_limit) {
  if (likely(state && state->ipv4_frag_state)) {
    pfwl_reordering_ipv4_fragmentation_set_per_host_memory_limit(
        state->ipv4_frag_state, per_host_memory_limit);
    return PFWL_STATE_UPDATE_SUCCESS;
  } else {
    return PFWL_STATE_UPDATE_FAILURE;
  }
}


uint8_t pfwl_ipv6_fragmentation_set_per_host_memory_limit(pfwl_state_t* state,
							  uint32_t per_host_memory_limit) {
  if (likely(state && state->ipv6_frag_state)) {
    pfwl_reordering_ipv6_fragmentation_set_per_host_memory_limit(
        state->ipv6_frag_state, per_host_memory_limit);
    return PFWL_STATE_UPDATE_SUCCESS;
  } else {
    return PFWL_STATE_UPDATE_FAILURE;
  }
}


uint8_t pfwl_ipv4_fragmentation_set_total_memory_limit(pfwl_state_t* state,
						       uint32_t total_memory_limit) {
  if (likely(state && state->ipv4_frag_state)) {
    pfwl_reordering_ipv4_fragmentation_set_total_memory_limit(
        state->ipv4_frag_state, total_memory_limit);
    return PFWL_STATE_UPDATE_SUCCESS;
  } else {
    return PFWL_STATE_UPDATE_FAILURE;
  }
}


uint8_t pfwl_ipv6_fragmentation_set_total_memory_limit(pfwl_state_t* state,
						       uint32_t total_memory_limit) {
  if (likely(state && state->ipv6_frag_state)) {
    pfwl_reordering_ipv6_fragmentation_set_total_memory_limit(
        state->ipv6_frag_state, total_memory_limit);
    return PFWL_STATE_UPDATE_SUCCESS;
  } else {
    return PFWL_STATE_UPDATE_FAILURE;
  }
}


uint8_t pfwl_ipv4_fragmentation_set_reassembly_timeout(pfwl_state_t* state,
						       uint8_t timeout_seconds) {
  if (likely(state && state->ipv4_frag_state)) {
    pfwl_reordering_ipv4_fragmentation_set_reassembly_timeout(
        state->ipv4_frag_state, timeout_seconds);
    return PFWL_STATE_UPDATE_SUCCESS;
  } else {
    return PFWL_STATE_UPDATE_FAILURE;
  }
}


uint8_t pfwl_ipv6_fragmentation_set_reassembly_timeout(pfwl_state_t* state,
						       uint8_t timeout_seconds) {
  if (likely(state && state->ipv6_frag_state)) {
    pfwl_reordering_ipv6_fragmentation_set_reassembly_timeout(
        state->ipv6_frag_state, timeout_seconds);
    return PFWL_STATE_UPDATE_SUCCESS;
  } else {
    return PFWL_STATE_UPDATE_FAILURE;
  }
}


uint8_t pfwl_ipv4_fragmentation_disable(pfwl_state_t* state) {
  if (likely(state && state->ipv4_frag_state)) {
    pfwl_reordering_disable_ipv4_fragmentation(state->ipv4_frag_state);
    state->ipv4_frag_state = NULL;
    return PFWL_STATE_UPDATE_SUCCESS;
  } else {
    return PFWL_STATE_UPDATE_FAILURE;
  }
}


uint8_t pfwl_ipv6_fragmentation_disable(pfwl_state_t* state) {
  if (likely(state && state->ipv6_frag_state)) {
    pfwl_reordering_disable_ipv6_fragmentation(state->ipv6_frag_state);
    state->ipv6_frag_state = NULL;
    return PFWL_STATE_UPDATE_SUCCESS;
  } else {
    return PFWL_STATE_UPDATE_FAILURE;
  }
}


uint8_t pfwl_tcp_reordering_enable(pfwl_state_t* state) {
  if (likely(state)) {
    state->tcp_reordering_enabled = 1;
    return PFWL_STATE_UPDATE_SUCCESS;
  } else {
    return PFWL_STATE_UPDATE_FAILURE;
  }
}


uint8_t pfwl_tcp_reordering_disable(pfwl_state_t* state) {
  if (likely(state)) {
    state->tcp_reordering_enabled = 0;
    return PFWL_STATE_UPDATE_SUCCESS;
  } else {
    return PFWL_STATE_UPDATE_FAILURE;
  }
}

uint8_t pfwl_enable_protocol(pfwl_state_t* state,
			     pfwl_protocol_l7 protocol) {
  if (protocol < PFWL_NUM_PROTOCOLS) {
    BITSET(state->protocols_to_inspect, protocol);
    ++state->active_protocols;
    return PFWL_STATE_UPDATE_SUCCESS;
  } else {
    return PFWL_STATE_UPDATE_FAILURE;
  }
}

uint8_t pfwl_disable_protocol(pfwl_state_t* state,
			      pfwl_protocol_l7 protocol) {
  if (protocol < PFWL_NUM_PROTOCOLS) {
    BITCLEAR(state->protocols_to_inspect, protocol);
    BITCLEAR(state->active_callbacks, protocol);
    --state->active_protocols;
    return PFWL_STATE_UPDATE_SUCCESS;
  } else {
    return PFWL_STATE_UPDATE_SUCCESS;
  }
}


uint8_t pfwl_inspect_all(pfwl_state_t* state) {
  unsigned char nonzero = ~0;
  memset(state->protocols_to_inspect, nonzero, BITNSLOTS(PFWL_NUM_PROTOCOLS));
  state->active_protocols = PFWL_NUM_PROTOCOLS;
  return PFWL_STATE_UPDATE_SUCCESS;
}


uint8_t pfwl_inspect_nothing(pfwl_state_t* state) {
  bzero(state->protocols_to_inspect, BITNSLOTS(PFWL_NUM_PROTOCOLS));

  state->active_protocols = 0;

  bzero(state->active_callbacks, PFWL_NUM_PROTOCOLS);
  return PFWL_STATE_UPDATE_SUCCESS;
}

uint8_t pfwl_skip_L7_parsing_by_port(pfwl_state_t* state, uint8_t l4prot,
				     uint16_t port, pfwl_protocol_l7 id) {
  pfwl_l7_skipping_infos_t* skinfos = malloc(sizeof(pfwl_l7_skipping_infos_t));
  memset(skinfos, 0, sizeof(pfwl_l7_skipping_infos_t));
  skinfos->key.l4prot = l4prot;
  skinfos->key.port = port;
  skinfos->protocol = id;
  HASH_ADD(hh, state->l7_skip, key, sizeof(skinfos->key), skinfos);
  return PFWL_STATE_UPDATE_SUCCESS;
}


void pfwl_terminate(pfwl_state_t* state) {
  if (likely(state)) {
    pfwl_http_disable_callbacks(state);
    pfwl_ipv4_fragmentation_disable(state);
    pfwl_ipv6_fragmentation_disable(state);
    pfwl_tcp_reordering_disable(state);

    pfwl_flow_table_delete_v4(state->db4, state->flow_cleaner_callback);
    pfwl_flow_table_delete_v6(state->db6, state->flow_cleaner_callback);
#ifdef WITH_PROMETHEUS
    pfwl_prometheus_terminate(state);
#endif
    for(size_t i = 0; i < PFWL_NUM_PROTOCOLS; i++){
      free(state->fields_extraction[i].fields);
    }
    free(state);
  }
}


pfwl_identification_result_t pfwl_get_protocol(pfwl_state_t* state,
					       const unsigned char* pkt,
					       uint32_t length,
					       uint32_t current_time) {
  pfwl_identification_result_t r;
  r.status = PFWL_STATUS_OK;
  pfwl_pkt_infos_t infos;
  memset(&infos, 0, sizeof(infos));
  uint8_t l3_status;

  r.status = pfwl_parse_L3_L4_headers(state, pkt, length, &infos, current_time);
  l3_status = r.status;
  r.protocol_l4 = infos.l4prot;

  if (unlikely(r.status == PFWL_STATUS_IP_FRAGMENT || r.status < 0)) {
    return r;
  }

  uint8_t skip_l7 = 0;
  uint16_t srcport = ntohs(infos.srcport);
  uint16_t dstport = ntohs(infos.dstport);
  pfwl_l7_skipping_infos_t* sk = NULL;
  pfwl_l7_skipping_infos_key_t key;
  memset(&key, 0, sizeof(key));
  key.l4prot = infos.l4prot;
  key.port = dstport;
  HASH_FIND(hh, state->l7_skip, &key, sizeof(pfwl_l7_skipping_infos_key_t), sk);
  if (sk) {
    skip_l7 = 1;
    r.protocol_l7 = sk->protocol;
  } else {
    key.port = srcport;
    HASH_FIND(hh, state->l7_skip, &key, sizeof(pfwl_l7_skipping_infos_key_t),
              sk);
    if (sk) {
      skip_l7 = 1;
      r.protocol_l7 = sk->protocol;
    }
  }

  if (!skip_l7) {
    if (infos.l4prot != IPPROTO_TCP && infos.l4prot != IPPROTO_UDP) {
      return r;
    }

    r.status = PFWL_STATUS_OK;
    /**
     * We return the status of pfwl_stateful_get_app_protocol call,
     * without giving informations on status returned
     * by pfwl_parse_L3_L4_headers. Basically we return the status which
     * provides more informations.
     */
    r = pfwl_stateful_get_app_protocol(state, &infos);
  }

  if (l3_status == PFWL_STATUS_IP_LAST_FRAGMENT) {
    free((unsigned char*)infos.pkt);
  }

  return r;
}


int8_t mc_pfwl_extract_packet_infos(pfwl_state_t* state,
				    const unsigned char* p_pkt,
				    uint32_t p_length,
				    pfwl_pkt_infos_t* pkt_infos,
				    uint32_t current_time, int tid) {
  if (unlikely(p_length == 0)) return PFWL_STATUS_OK;
  uint8_t version;
#if __BYTE_ORDER == __LITTLE_ENDIAN
  version = (p_pkt[0] >> 4) & 0x0F;
#elif __BYTE_ORDER == __BIG_ENDIAN
  version = (p_pkt[0] << 4) & 0x0F;
#else
#error "Please fix <bits/endian.h>"
#endif

  unsigned char* pkt = (unsigned char*)p_pkt;
  uint32_t length = p_length;
  uint16_t offset;
  uint8_t more_fragments;

  pkt_infos->l4prot = 0;
  pkt_infos->srcport = 0;
  pkt_infos->dstport = 0;

  /** Offset starting from the beginning of p_pkt. **/
  uint32_t application_offset;
  /**
   * Offset starting from the last identified IPv4 or IPv6 header
   * (used to support tunneling).
   **/
  uint32_t relative_offset;
  uint32_t tmp;
  uint8_t next_header, stop = 0;

  int8_t to_return = PFWL_STATUS_OK;

  struct ip6_hdr* ip6 = NULL;
  struct iphdr* ip4 = NULL;

  if (version == PFWL_IP_VERSION_4) { /** IPv4 **/
    ip4 = (struct iphdr*)(p_pkt);
    uint16_t tot_len = ntohs(ip4->tot_len);

#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
    if (unlikely(length < (sizeof(struct iphdr)) || tot_len > length ||
                 tot_len <= ((ip4->ihl) * 4))) {
      return PFWL_ERROR_L3_TRUNCATED_PACKET;
    }
#endif
    /**
     * At this point we are sure that tot_len<=length, so we set
     * length=tot_len. In some cases indeed there may be an L2 padding
     * at the end of the packet, so capture length (length) may be
     * greater than the effective datagram length.
     */
    length = tot_len;

    offset = ntohs(ip4->frag_off);
    if (unlikely((offset & PFWL_IPv4_FRAGMENTATION_MF))) {
      more_fragments = 1;
    } else
      more_fragments = 0;

    /**
     * Offset is in 8-byte blocks. Multiplying by 8 correspond to a
     * right shift by 3 position, but the offset was 13 bit, so it can
     * still fit in a 16 bit integer.
     */
    offset = (offset & PFWL_IPv4_FRAGMENTATION_OFFSET_MASK) * 8;

    if (likely((!more_fragments) && (offset == 0))) {
      pkt = (unsigned char*)p_pkt;
    } else if (state->ipv4_frag_state != NULL) {
      pkt = pfwl_reordering_manage_ipv4_fragment(state->ipv4_frag_state, p_pkt,
                                                current_time, offset,
                                                more_fragments, tid);
      if (pkt == NULL) {
        return PFWL_STATUS_IP_FRAGMENT;
      }
      to_return = PFWL_STATUS_IP_LAST_FRAGMENT;
      ip4 = (struct iphdr*)(pkt);
      length = ntohs(((struct iphdr*)(pkt))->tot_len);
    } else {
      return PFWL_STATUS_IP_FRAGMENT;
    }

    pkt_infos->src_addr_t.ipv4_srcaddr = ip4->saddr;
    pkt_infos->dst_addr_t.ipv4_dstaddr = ip4->daddr;

    application_offset = (ip4->ihl) * 4;
    relative_offset = application_offset;

    next_header = ip4->protocol;
  } else if (version == PFWL_IP_VERSION_6) { /** IPv6 **/
    ip6 = (struct ip6_hdr*)(pkt);
    uint16_t tot_len =
        ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) + sizeof(struct ip6_hdr);
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
    if (unlikely(tot_len > length)) {
      return PFWL_ERROR_L3_TRUNCATED_PACKET;
    }
#endif

    /**
     * At this point we are sure that tot_len<=length, so we set
     * length=tot_len. In some cases indeed there may be an L2 padding
     * at the end of the packet, so capture length (length) may be
     * greater than the effective datagram length.
     */
    length = tot_len;

    pkt_infos->src_addr_t.ipv6_srcaddr = ip6->ip6_src;
    pkt_infos->dst_addr_t.ipv6_dstaddr = ip6->ip6_dst;

    application_offset = sizeof(struct ip6_hdr);
    relative_offset = application_offset;
    next_header = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
  } else {
    return PFWL_ERROR_WRONG_IPVERSION;
  }

  while (!stop) {
    switch (next_header) {
      case IPPROTO_TCP: { /* TCP */
        struct tcphdr* tcp = (struct tcphdr*)(pkt + application_offset);
#ifdef PFWL_ENABLE_L4_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct tcphdr) > length ||
                     application_offset + tcp->doff * 4 > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          return PFWL_ERROR_L4_TRUNCATED_PACKET;
        }
#endif
        pkt_infos->srcport = tcp->source;
        pkt_infos->dstport = tcp->dest;
        pkt_infos->l4offset = application_offset;
        application_offset += (tcp->doff * 4);
        stop = 1;
      } break;
      case IPPROTO_UDP: { /* UDP */
        struct udphdr* udp = (struct udphdr*)(pkt + application_offset);
#ifdef PFWL_ENABLE_L4_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct udphdr) > length ||
                     application_offset + ntohs(udp->len) > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          return PFWL_ERROR_L4_TRUNCATED_PACKET;
        }
#endif
        pkt_infos->srcport = udp->source;
        pkt_infos->dstport = udp->dest;
        pkt_infos->l4offset = application_offset;
        application_offset += 8;
        stop = 1;
      } break;
      case IPPROTO_HOPOPTS: { /* Hop by hop options */
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct ip6_hbh) > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          return PFWL_ERROR_L3_TRUNCATED_PACKET;
        }
#endif
        if (likely(version == 6)) {
          struct ip6_hbh* hbh_hdr = (struct ip6_hbh*)(pkt + application_offset);
          tmp = (8 + hbh_hdr->ip6h_len * 8);
          application_offset += tmp;
          relative_offset += tmp;
          next_header = hbh_hdr->ip6h_nxt;
        } else {
          if (unlikely(pkt != p_pkt)) free(pkt);
          return PFWL_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
        }
      } break;
      case IPPROTO_DSTOPTS: { /* Destination options */
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct ip6_dest) > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          return PFWL_ERROR_L3_TRUNCATED_PACKET;
        }
#endif
        if (likely(version == 6)) {
          struct ip6_dest* dst_hdr =
              (struct ip6_dest*)(pkt + application_offset);
          tmp = (8 + dst_hdr->ip6d_len * 8);
          application_offset += tmp;
          relative_offset += tmp;
          next_header = dst_hdr->ip6d_nxt;
        } else {
          if (unlikely(pkt != p_pkt)) free(pkt);
          return PFWL_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
        }
      } break;
      case IPPROTO_ROUTING: { /* Routing header */
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct ip6_rthdr) > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          return PFWL_ERROR_L3_TRUNCATED_PACKET;
        }
#endif
        if (likely(version == 6)) {
          struct ip6_rthdr* rt_hdr =
              (struct ip6_rthdr*)(pkt + application_offset);
          tmp = (8 + rt_hdr->ip6r_len * 8);
          application_offset += tmp;
          relative_offset += tmp;
          next_header = rt_hdr->ip6r_nxt;
        } else {
          if (unlikely(pkt != p_pkt)) free(pkt);
          return PFWL_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
        }
      } break;
      case IPPROTO_FRAGMENT: { /* Fragment header */
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct ip6_frag) > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          return PFWL_ERROR_L3_TRUNCATED_PACKET;
        }
#endif
        if (likely(version == 6)) {
          if (state->ipv6_frag_state) {
            struct ip6_frag* frg_hdr =
                (struct ip6_frag*)(pkt + application_offset);
            uint16_t offset = ((frg_hdr->ip6f_offlg & IP6F_OFF_MASK) >> 3) * 8;
            uint8_t more_fragments =
                ((frg_hdr->ip6f_offlg & IP6F_MORE_FRAG)) ? 1 : 0;
            offset = ntohs(offset);
            uint32_t fragment_size =
                ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) +
                sizeof(struct ip6_hdr) - relative_offset -
                sizeof(struct ip6_frag);

            /**
             * If this fragment has been obtained from a
             * defragmentation (e.g. tunneling), then delete
             * it after that the defragmentation support has
             * copied it.
             */
            unsigned char* to_delete = NULL;
            if (pkt != p_pkt) {
              to_delete = pkt;
            }

            /**
             * For our purposes, from the unfragmentable part
             * we need only the IPv6 header, any other
             * optional header can be discarded, for this
             * reason we copy only the IPv6 header bytes.
             */
            pkt = pfwl_reordering_manage_ipv6_fragment(
                state->ipv6_frag_state, (unsigned char*)ip6,
                sizeof(struct ip6_hdr),
                ((unsigned char*)ip6) + relative_offset +
                    sizeof(struct ip6_frag),
                fragment_size, offset, more_fragments, frg_hdr->ip6f_ident,
                frg_hdr->ip6f_nxt, current_time, tid);

            if (to_delete) free(to_delete);

            if (pkt == NULL) {
              return PFWL_STATUS_IP_FRAGMENT;
            }

            to_return = PFWL_STATUS_IP_LAST_FRAGMENT;
            next_header = IPPROTO_IPV6;
            length = ((struct ip6_hdr*)(pkt))->ip6_ctlun.ip6_un1.ip6_un1_plen +
                     sizeof(struct ip6_hdr);
            /**
             * Force the next iteration to analyze the
             * reassembled IPv6 packet.
             **/
            application_offset = relative_offset = 0;
          } else {
            return PFWL_STATUS_IP_FRAGMENT;
          }
        } else {
          if (unlikely(pkt != p_pkt)) free(pkt);
          return PFWL_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
        }
      } break;
      case IPPROTO_IPV6: /** 6in4 and 6in6 tunneling **/
        /** The real packet is now ipv6. **/
        version = 6;
        ip6 = (struct ip6_hdr*)(pkt + application_offset);
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
        if (unlikely(ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) +
                         sizeof(struct ip6_hdr) >
                     length - application_offset)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          return PFWL_ERROR_L3_TRUNCATED_PACKET;
        }
#endif

        pkt_infos->src_addr_t.ipv6_srcaddr = ip6->ip6_src;
        pkt_infos->dst_addr_t.ipv6_dstaddr = ip6->ip6_dst;

        application_offset += sizeof(struct ip6_hdr);
        relative_offset = sizeof(struct ip6_hdr);
        next_header = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        break;
      case 4: /* 4in4 and 4in6 tunneling */
        /** The real packet is now ipv4. **/
        version = 4;
        ip4 = (struct iphdr*)(pkt + application_offset);
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct iphdr) > length ||
                     application_offset + ((ip4->ihl) * 4) > length ||
                     application_offset + ntohs(ip4->tot_len) > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          return PFWL_ERROR_L3_TRUNCATED_PACKET;
        }
#endif
        pkt_infos->src_addr_t.ipv4_srcaddr = ip4->saddr;
        pkt_infos->dst_addr_t.ipv4_dstaddr = ip4->daddr;
        next_header = ip4->protocol;
        tmp = (ip4->ihl) * 4;
        application_offset += tmp;
        relative_offset = tmp;
        break;
      default:
        stop = 1;
        pkt_infos->l4offset = application_offset;
        break;
    }
  }

  pkt_infos->l4prot = next_header;
#ifdef PFWL_ENABLE_L4_TRUNCATION_PROTECTION
  if (unlikely(application_offset > length)) {
    if (unlikely(pkt != p_pkt)) free(pkt);
    return PFWL_ERROR_L4_TRUNCATED_PACKET;
  }
#endif
  pkt_infos->processing_time = current_time;
  pkt_infos->pkt = pkt;
  pkt_infos->l7offset = application_offset;
  pkt_infos->data_length = length - application_offset;
  pkt_infos->ip_version = version;
  return to_return;
}

int8_t pfwl_parse_L3_L4_headers(pfwl_state_t* state,
				const unsigned char* p_pkt, uint32_t p_length,
				pfwl_pkt_infos_t* pkt_infos,
				uint32_t current_time) {
  /**
   * We can pass any thread id, indeed in this case we don't
   * need lock synchronization.
   **/
  return mc_pfwl_extract_packet_infos(state, p_pkt, p_length, pkt_infos,
                                     current_time, 0);
}


pfwl_identification_result_t pfwl_stateful_get_app_protocol(
    pfwl_state_t* state, pfwl_pkt_infos_t* pkt_infos) {
  pfwl_identification_result_t r;
  r.status = PFWL_STATUS_OK;

  pfwl_flow_infos_t* flow_infos = NULL;
  ipv4_flow_t* ipv4_flow = NULL;
  ipv6_flow_t* ipv6_flow = NULL;

  if (pkt_infos->ip_version == PFWL_IP_VERSION_4) {
    ipv4_flow = pfwl_flow_table_find_or_create_flow_v4(state, pkt_infos);
    if (ipv4_flow) flow_infos = &(ipv4_flow->infos);
  } else {
    ipv6_flow = pfwl_flow_table_find_or_create_flow_v6(state, pkt_infos);
    if (ipv6_flow) flow_infos = &(ipv6_flow->infos);
  }

  if (unlikely(flow_infos == NULL)) {
    r.status = PFWL_ERROR_MAX_FLOWS;
    return r;
  }

  r = pfwl_stateless_get_app_protocol(state, flow_infos, pkt_infos);

  if (r.status == PFWL_STATUS_TCP_CONNECTION_TERMINATED) {
    if (ipv4_flow != NULL) {
      pfwl_flow_table_delete_flow_v4(state->db4, state->flow_cleaner_callback,
                                    ipv4_flow);
    } else {
      pfwl_flow_table_delete_flow_v6(state->db6, state->flow_cleaner_callback,
                                    ipv6_flow);
    }
  }
  return r;
}


void pfwl_init_flow_infos(pfwl_state_t* state,
			  pfwl_flow_infos_t* flow_infos, uint8_t l4prot) {
  pfwl_protocol_l7 i;

  for (i = 0; i < BITNSLOTS(PFWL_NUM_PROTOCOLS); i++) {
    flow_infos->possible_matching_protocols[i] = state->protocols_to_inspect[i];
  }
  flow_infos->possible_protocols = state->active_protocols;

  flow_infos->l7prot = PFWL_PROTOCOL_NOT_DETERMINED;
  flow_infos->trials = 0;
  flow_infos->tcp_reordering_enabled = state->tcp_reordering_enabled;
  flow_infos->last_rebuilt_tcp_data = NULL;
  bzero(&(flow_infos->tracking), sizeof(pfwl_tracking_informations_t));
}


pfwl_identification_result_t pfwl_stateless_get_app_protocol(pfwl_state_t* state,
							     pfwl_flow_infos_t* flow,
							     pfwl_pkt_infos_t* pkt_infos) {
  pfwl_identification_result_t r;
  r.status = PFWL_STATUS_OK;
  r.protocol_l4 = pkt_infos->l4prot;
  r.user_flow_data = (flow->tracking.udata);
  pfwl_protocol_l7 i;

  uint8_t check_result = PFWL_PROTOCOL_NO_MATCHES;
  const pfwl_protocol_l7* well_known_ports;
  const unsigned char* app_data = pkt_infos->pkt + pkt_infos->l7offset;
  uint32_t data_length = pkt_infos->data_length;
  pfwl_tcp_reordering_reordered_segment_t seg;
  seg.status = PFWL_TCP_REORDERING_STATUS_IN_ORDER;
  seg.data = NULL;
  seg.connection_terminated = 0;

  if(data_length){
    ++flow->tracking.num_packets;
  }

  if (flow->l7prot < PFWL_PROTOCOL_NOT_DETERMINED) {
    r.protocol_l7 = flow->l7prot;
    if (pkt_infos->l4prot == IPPROTO_TCP) {
      if (flow->tcp_reordering_enabled) {
        seg = pfwl_reordering_tcp_track_connection(pkt_infos, &(flow->tracking));

        if (seg.status == PFWL_TCP_REORDERING_STATUS_OUT_OF_ORDER) {
          r.status = PFWL_STATUS_TCP_OUT_OF_ORDER;
          return r;
        } else if (seg.status == PFWL_TCP_REORDERING_STATUS_REBUILT) {
          app_data = seg.data;
          data_length = seg.data_length;
          if(flow->last_rebuilt_tcp_data){
            free((void*) flow->last_rebuilt_tcp_data);
          }
          flow->last_rebuilt_tcp_data = app_data;
        }
      } else {
        seg.connection_terminated = pfwl_reordering_tcp_track_connection_light(
            pkt_infos, &(flow->tracking));
      }

      if ((BITTEST(state->active_callbacks, flow->l7prot))
          && data_length != 0) {
        (*(callbacks_manager[flow->l7prot]))(state, pkt_infos, app_data,
                                             data_length, &(flow->tracking));
      }
    } else if (pkt_infos->l4prot == IPPROTO_UDP &&
               BITTEST(state->active_callbacks, flow->l7prot)) {
      (*(callbacks_manager[flow->l7prot]))(state, pkt_infos, app_data,
                                           data_length, &(flow->tracking));
    }

    pfwl_tracking_informations_t* t = &(flow->tracking);
    if (flow->l7prot < PFWL_NUM_PROTOCOLS &&
        state->fields_extraction[flow->l7prot].fields_num) {
      pfwl_protocol_descriptor_t descr = protocols_descriptors[flow->l7prot];
      size_t fields_num = descr.extracted_fields_num;
      r.protocol_fields = (*descr.get_extracted_fields)(t);
      memset(r.protocol_fields, 0, sizeof(pfwl_field_t)*fields_num);
      (*(descr.dissector))(state, pkt_infos, app_data, data_length, t);
      r.protocol_fields_num = fields_num;
    }

    if (seg.connection_terminated) {
      r.status = PFWL_STATUS_TCP_CONNECTION_TERMINATED;
    }
    return r;
  } else if (flow->l7prot == PFWL_PROTOCOL_NOT_DETERMINED) {
    if (pkt_infos->l4prot == IPPROTO_TCP && state->active_protocols > 0) {
      well_known_ports = pfwl_well_known_ports_association_tcp;
      if (flow->tcp_reordering_enabled) {
        seg = pfwl_reordering_tcp_track_connection(pkt_infos, &(flow->tracking));

        if (seg.status == PFWL_TCP_REORDERING_STATUS_OUT_OF_ORDER) {
          r.status = PFWL_STATUS_TCP_OUT_OF_ORDER;
          r.protocol_l7 = PFWL_PROTOCOL_UNKNOWN;
          return r;
        } else if (seg.status == PFWL_TCP_REORDERING_STATUS_REBUILT) {
          app_data = seg.data;
          data_length = seg.data_length;
          if(flow->last_rebuilt_tcp_data){
            free((void*) flow->last_rebuilt_tcp_data);
          }
          flow->last_rebuilt_tcp_data = app_data;
        }
      } else {
        if (pfwl_reordering_tcp_track_connection_light(pkt_infos,
                                                      &(flow->tracking)))
          r.status = PFWL_STATUS_TCP_CONNECTION_TERMINATED;
      }
    } else if (pkt_infos->l4prot == IPPROTO_UDP &&
               state->active_protocols > 0) {
      well_known_ports = pfwl_well_known_ports_association_udp;
    } else {
      return r;
    }

    /**
     * If we have no payload we don't do anything. We already
     * invoked the TCP reordering to update the connection state.
     */
    if (data_length == 0) {
      r.protocol_l7 = flow->l7prot;
      return r;
    }

    pfwl_protocol_l7 first_protocol_to_check;
    pfwl_protocol_l7 checked_protocols = 0;

    if ((first_protocol_to_check = well_known_ports[pkt_infos->srcport]) ==
            PFWL_PROTOCOL_UNKNOWN &&
        (first_protocol_to_check = well_known_ports[pkt_infos->dstport]) ==
            PFWL_PROTOCOL_UNKNOWN) {
      first_protocol_to_check = 0;
    }

    for (i = first_protocol_to_check; checked_protocols < PFWL_NUM_PROTOCOLS;
         i = (i + 1) % PFWL_NUM_PROTOCOLS, ++checked_protocols) {
      if (BITTEST(flow->possible_matching_protocols, i)) {
        pfwl_protocol_descriptor_t descr = protocols_descriptors[i];
        pfwl_tracking_informations_t* t = &(flow->tracking);
        size_t fields_num = descr.extracted_fields_num;
        if(descr.get_extracted_fields){
          memset((*descr.get_extracted_fields)(t), 0, sizeof(pfwl_field_t)*fields_num);
        }
        check_result = (*(descr.dissector))(state, pkt_infos, app_data,
                                          data_length, t);
        if (check_result == PFWL_PROTOCOL_MATCHES) {
          flow->l7prot = i;
          r.protocol_l7 = flow->l7prot;

          if (flow->l7prot < PFWL_NUM_PROTOCOLS &&
              state->fields_extraction[flow->l7prot].fields_num) {
            r.protocol_fields = (*descr.get_extracted_fields)(t);
            r.protocol_fields_num = fields_num;
          }

          if (seg.connection_terminated) {
            r.status = PFWL_STATUS_TCP_CONNECTION_TERMINATED;
          }
#ifdef WITH_PROMETHEUS
          flow->prometheus_counter_packets = pfwl_prometheus_counter_create(
              state->prometheus_stats, "packets", pkt_infos, flow->l7prot);
          flow->prometheus_counter_bytes = pfwl_prometheus_counter_create(
              state->prometheus_stats, "bytes", pkt_infos, flow->l7prot);
#endif
          return r;
        } else if (check_result == PFWL_PROTOCOL_NO_MATCHES) {
          BITCLEAR(flow->possible_matching_protocols, i);
          --(flow->possible_protocols);
        }
      }
    }

    /**
     * If all the protocols don't match or if we still have
     * ambiguity after the maximum number of trials, then the
     * library was unable to identify the protocol.
     **/
    if (flow->possible_protocols == 0 ||
        (state->max_trials != 0 &&
         unlikely(++flow->trials == state->max_trials))) {
      flow->l7prot = PFWL_PROTOCOL_UNKNOWN;
    }
  }

  r.protocol_l7 = flow->l7prot;

  if(flow->last_rebuilt_tcp_data){
    free((void*) flow->last_rebuilt_tcp_data);
    flow->last_rebuilt_tcp_data = NULL;
  }

  if (seg.connection_terminated) {
    r.status = PFWL_STATUS_TCP_CONNECTION_TERMINATED;
  }
  return r;
}


pfwl_protocol_l7 pfwl_guess_protocol(pfwl_pkt_infos_t* pkt_infos) {
  pfwl_protocol_l7 r = PFWL_PROTOCOL_UNKNOWN;
  if (pkt_infos->l4prot == IPPROTO_TCP) {
    r = pfwl_well_known_ports_association_tcp[pkt_infos->srcport];
    if (r == PFWL_PROTOCOL_UNKNOWN)
      r = pfwl_well_known_ports_association_tcp[pkt_infos->dstport];
  } else if (pkt_infos->l4prot == IPPROTO_UDP) {
    r = pfwl_well_known_ports_association_udp[pkt_infos->srcport];
    if (r == PFWL_PROTOCOL_UNKNOWN)
      r = pfwl_well_known_ports_association_udp[pkt_infos->dstport];
  } else {
    r = PFWL_PROTOCOL_UNKNOWN;
  }
  return r;
}


uint8_t pfwl_set_protocol_accuracy(pfwl_state_t *state,
                                  pfwl_protocol_l7 protocol,
                                  pfwl_inspector_accuracy accuracy) {
  if (state) {
    state->inspectors_accuracy[protocol] = accuracy;
    return PFWL_STATE_UPDATE_SUCCESS;
  } else {
    return PFWL_STATE_UPDATE_FAILURE;
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
             " reached.";
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


const char* const pfwl_get_protocol_string(pfwl_protocol_l7 protocol) {
  if (protocol < PFWL_NUM_PROTOCOLS) {
    return protocols_descriptors[protocol].name;
  } else {
    return "Unknown";
  }
}

pfwl_protocol_l7 pfwl_get_protocol_id(const char* const string) {
  size_t i;
  for (i = 0; i < (size_t)PFWL_NUM_PROTOCOLS; i++) {
    if (strcasecmp(string, protocols_descriptors[i].name) == 0) {
      return (pfwl_protocol_l7)i;
      ;
    }
  }
  return PFWL_NUM_PROTOCOLS;
}

static const char* protocols_strings[PFWL_NUM_PROTOCOLS];

const char** const pfwl_get_protocols_strings() {
  size_t i;
  for (i = 0; i < (size_t)PFWL_NUM_PROTOCOLS; i++) {
    protocols_strings[i] = protocols_descriptors[i].name;
  }
  return protocols_strings;
}


uint8_t pfwl_set_flow_cleaner_callback(pfwl_state_t* state,
				       pfwl_flow_cleaner_callback* cleaner) {
  state->flow_cleaner_callback = cleaner;
  return PFWL_STATE_UPDATE_SUCCESS;
}


uint8_t pfwl_protocol_field_add(pfwl_state_t* state,
				pfwl_protocol_l7 protocol,
				int field_type){
  if(state){
    state->fields_extraction[protocol].fields[field_type] = 1;
    state->fields_extraction[protocol].fields_num++;
    pfwl_set_protocol_accuracy(state, protocol, PFWL_INSPECTOR_ACCURACY_HIGH);  // TODO: mmm, the problem is that we do not set back the original accuracy when doing field_remove
    return PFWL_STATE_UPDATE_SUCCESS;
  }else{
    return PFWL_STATE_UPDATE_FAILURE;
  }
}


uint8_t pfwl_protocol_field_remove(pfwl_state_t* state,
                                    pfwl_protocol_l7 protocol,
                                    int field_type){
  if(state){
    state->fields_extraction[protocol].fields[field_type] = 0;
    state->fields_extraction[protocol].fields_num--;
    return PFWL_STATE_UPDATE_SUCCESS;
  }else{
    return PFWL_STATE_UPDATE_FAILURE;
  }
}


uint8_t pfwl_protocol_field_required(pfwl_state_t* state,
                                      pfwl_protocol_l7 protocol,
                                      int field_type) {
  if(state){
    return state->fields_extraction[protocol].fields[field_type];
  }else{
    return 0;
  }
}


uint8_t pfwl_callbacks_fields_set_udata(pfwl_state_t* state,
                                        void* udata) {
    if(state){
        state->callbacks_udata = udata;
        return PFWL_STATE_UPDATE_SUCCESS;
    }else{
        return PFWL_STATE_UPDATE_FAILURE;
    }
}


static uint16_t pfwl_check_dtype(const u_char* packet,
				 uint16_t type,
				 uint16_t off)
{
  uint32_t dlink_offset = off;

  // define vlan header
  const struct vlan_hdr *vlan_header = NULL;
  // define mpls 
  union mpls {
    uint32_t u32;
    struct mpls_header mpls;
  } mpls;
  
  switch(type)
    {
      /**
	 NOTE:
	 The check for IPv4 or IPv6 type is done later 
	 in another function
	 TODO: ARP check
      **/
      // VLAN
    case ETHERTYPE_VLAN:
      vlan_header = (struct vlan_hdr *) (packet + dlink_offset);
      type = ntohs(vlan_header->type);
      // double tagging for 802.1Q
      if(type == 0x8100) {
	dlink_offset += 4;
	vlan_header = (struct vlan_hdr *) (packet + dlink_offset);
      }
      dlink_offset += 4;
      break;
      // MPLS
    case ETHERTYPE_MPLS_UNI:
    case ETHERTYPE_MPLS_MULTI:
      mpls.u32 = *((uint32_t *) &packet[dlink_offset]);
      mpls.u32 = ntohl(mpls.u32);
      dlink_offset += 4;
      // multiple MPLS fields
      while(!mpls.mpls.s) {
	mpls.u32 = *((uint32_t *) &packet[dlink_offset]);
	mpls.u32 = ntohl(mpls.u32);
	dlink_offset += 4;
      }
      break;
    }
  return dlink_offset;
}

uint32_t pfwl_parse_datalink(const u_char* packet,
			     struct pcap_pkthdr header,
			     pcap_t* pcap_handle) {

  // check parameters
  if(!packet || !pcap_handle)
    return -1;

  // len and offset
  uint16_t type = 0, eth_type_1 = 0;
  uint16_t wifi_len = 0, radiotap_len = 0, fc;
  uint16_t dlink_offset = 0;

  // define ethernet header
  struct ether_header* ether_header = NULL;
  // define radio_tap header
  struct radiotap_hdr* radiotap_header = NULL;
  // define wifi header
  struct wifi_hdr* wifi_header = NULL;
  // define llc header
  struct llc_snap_hdr* llc_snap_header = NULL;
  
  // check the datalink type to cast properly datalink header
  const int datalink_type = pcap_datalink(pcap_handle);
  switch(datalink_type) {
    
   /** IEEE 802.3 Ethernet - 1 **/
   case DLT_EN10MB:
     printf("Datalink type: Ethernet\n");
     ether_header = (struct ether_header*)(packet);
     // set datalink offset
     dlink_offset = ETHHDR_SIZE;
     type = ntohs(ether_header->ether_type);
     if(type <= 1500) eth_type_1 = 1; // ethernet I - followed by llc snap 05DC
     // check for LLC layer with SNAP extension
     if(eth_type_1) {
       if(packet[dlink_offset] == SNAP) {
     	 llc_snap_header = (struct llc_snap_hdr *)(packet + dlink_offset);
     	 type = llc_snap_header->type; // LLC type is the l3 proto type
     	 dlink_offset += 8;
       }
     }
     break;
     
   /** Linux Cooked Capture - 113 **/
   case DLT_LINUX_SLL:
     type = (packet[dlink_offset + 14] << 8) + packet[dlink_offset + 15];
     dlink_offset = 16;
     break;

   /** Radiotap link-layer - 127 **/
   case DLT_IEEE802_11_RADIO:
     radiotap_header = (struct radiotap_hdr *) packet;
     radiotap_len = radiotap_header->len;
     // Check Bad FCS presence
     if((radiotap_header->flags & BAD_FCS) == BAD_FCS) {
       return -1;
     }
     // Calculate 802.11 header length (variable)
     wifi_header = (struct wifi_hdr*)(packet + radiotap_len);
     fc = wifi_header->fc; // FRAME CONTROL BYTES
     
     // check wifi data presence
     if(FCF_TYPE(fc) == WIFI_DATA) {
       if((FCF_TO_DS(fc) && FCF_FROM_DS(fc) == 0x0) ||
	  (FCF_TO_DS(fc) == 0x0 && FCF_FROM_DS(fc)))
	 wifi_len = 26; /* + 4 byte fcs */
     }
     // no data frames
     else
       break;
     // Wifi data present - check LLC
     llc_snap_header = (struct llc_snap_hdr*)(packet + wifi_len + radiotap_len);
     if(llc_snap_header->dsap == SNAP)
       type = ntohs(llc_snap_header->type);
     else {
       printf("Probably a wifi packet of with data encription. Discard\n");
       return -1;
     }
     dlink_offset = radiotap_len + wifi_len + sizeof(struct llc_snap_hdr);
     break;

   /** LINKTYPE_IEEE802_5 - 6 **/
   case DLT_IEEE802:
     dlink_offset = TOKENRING_SIZE;
     break;

   /** LINKTYPE_SLIP - 8 **/
   case DLT_SLIP:
     dlink_offset = SLIPHDR_SIZE;
     break;

   /** LINKTYPE_PPP - 09 **/
   case DLT_PPP:
     dlink_offset = PPPHDR_SIZE;
     break;
     
   /** LINKTYPE_FDDI - 10 **/
   case DLT_FDDI:
     dlink_offset = FDDIHDR_SIZE;
     break;

   /** LINKTYPE_RAW - 101 **/
   case DLT_RAW:
     dlink_offset = RAWHDR_SIZE;
     break;

   /** LINKTYPE_LOOP - 108 **/
   case DLT_LOOP:
   /** LINKTYPE_NULL - 0 **/
   case DLT_NULL:
     dlink_offset = LOOPHDR_SIZE;
     break;

   default:
     perror("unsupported interface type\n");
     break;
  }
  
  dlink_offset = pfwl_check_dtype(packet, type, dlink_offset);
  
  return (uint32_t) dlink_offset;
}
