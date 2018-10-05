/*
 * peafowl.c
 *
 * Created on: 19/09/2012
 * =========================================================================
 *  Copyright (C) 2012-2013, Daniele De Sensi (d.desensi.software@gmail.com)
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

static const pfwl_protocol_l7_t const
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

static const pfwl_protocol_l7_t const
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
  pfwl_dissector dissector;
  int extracted_fields_num;
}pfwl_protocol_descriptor_t;

static const pfwl_protocol_descriptor_t const protocols_descriptors[PFWL_NUM_PROTOCOLS] =
  {
    [PFWL_PROTOCOL_DHCP]     = {"DHCP"    , check_dhcp    , 0},
    [PFWL_PROTOCOL_DHCPv6]   = {"DHCPv6"  , check_dhcpv6  , 0},
    [PFWL_PROTOCOL_DNS]      = {"DNS"     , check_dns     , PFWL_FIELDS_DNS_NUM},
    [PFWL_PROTOCOL_MDNS]     = {"MDNS"    , check_mdns    , 0},
    [PFWL_PROTOCOL_SIP]      = {"SIP"     , check_sip     , PFWL_FIELDS_SIP_NUM},
    [PFWL_PROTOCOL_RTP]      = {"RTP"     , check_rtp     , 0},
    [PFWL_PROTOCOL_SSH]      = {"SSH"     , check_ssh     , 0},
    [PFWL_PROTOCOL_SKYPE]    = {"Skype"   , check_skype   , 0},
    [PFWL_PROTOCOL_NTP]      = {"NTP"     , check_ntp     , 0},
    [PFWL_PROTOCOL_BGP]      = {"BGP"     , check_bgp     , 0},
    [PFWL_PROTOCOL_HTTP]     = {"HTTP"    , check_http    , PFWL_FIELDS_HTTP_NUM},
    [PFWL_PROTOCOL_SMTP]     = {"SMTP"    , check_smtp    , 0},
    [PFWL_PROTOCOL_POP3]     = {"POP3"    , check_pop3    , 0},
    [PFWL_PROTOCOL_IMAP]     = {"IMAP"    , check_imap    , 0},
    [PFWL_PROTOCOL_SSL]      = {"SSL"     , check_ssl     , PFWL_FIELDS_SSL_NUM},
    [PFWL_PROTOCOL_HANGOUT]  = {"Hangout" , check_hangout , 0},
    [PFWL_PROTOCOL_WHATSAPP] = {"WhatsApp", check_whatsapp, 0},
    [PFWL_PROTOCOL_TELEGRAM] = {"Telegram", check_telegram, 0},
    [PFWL_PROTOCOL_DROPBOX]  = {"Dropbox" , check_dropbox , 0},
    [PFWL_PROTOCOL_SPOTIFY]  = {"Spotify" , check_spotify , 0},
};

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
    pfwl_flow_table_delete(state->flow_table, NULL);
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
    size_t num_callbacks = protocols_descriptors[i].extracted_fields_num;
    state->fields_extraction[i].fields = (uint8_t*) malloc(sizeof(uint8_t)*num_callbacks);
    state->fields_extraction[i].fields_num = 0;
    for(size_t j = 0; j < num_callbacks; j++){
      state->fields_extraction[i].fields[j] = 0;
    }
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
  return 1;
}

uint8_t pfwl_ipv4_fragmentation_enable(pfwl_state_t* state,
                                      uint16_t table_size) {
  if (likely(state)) {
    state->ipv4_frag_state =
        pfwl_reordering_enable_ipv4_fragmentation(table_size);
    if (state->ipv4_frag_state)
      return 1;
    else
      return 0;
  } else
    return 0;
}

uint8_t pfwl_ipv6_fragmentation_enable(pfwl_state_t* state,
                                      uint16_t table_size) {
  if (likely(state)) {
    state->ipv6_frag_state =
        pfwl_reordering_enable_ipv6_fragmentation(table_size);
    if (state->ipv6_frag_state)
      return 1;
    else
      return 0;
  } else {
    return 0;
  }
}

uint8_t pfwl_ipv4_fragmentation_set_per_host_memory_limit(
    pfwl_state_t* state, uint32_t per_host_memory_limit) {
  if (likely(state && state->ipv4_frag_state)) {
    pfwl_reordering_ipv4_fragmentation_set_per_host_memory_limit(
        state->ipv4_frag_state, per_host_memory_limit);
    return 1;
  } else {
    return 0;
  }
}

uint8_t pfwl_ipv6_fragmentation_set_per_host_memory_limit(
    pfwl_state_t* state, uint32_t per_host_memory_limit) {
  if (likely(state && state->ipv6_frag_state)) {
    pfwl_reordering_ipv6_fragmentation_set_per_host_memory_limit(
        state->ipv6_frag_state, per_host_memory_limit);
    return 1;
  } else {
    return 0;
  }
}

uint8_t pfwl_ipv4_fragmentation_set_total_memory_limit(
    pfwl_state_t* state, uint32_t total_memory_limit) {
  if (likely(state && state->ipv4_frag_state)) {
    pfwl_reordering_ipv4_fragmentation_set_total_memory_limit(
        state->ipv4_frag_state, total_memory_limit);
    return 1;
  } else {
    return 0;
  }
}

uint8_t pfwl_ipv6_fragmentation_set_total_memory_limit(
    pfwl_state_t* state, uint32_t total_memory_limit) {
  if (likely(state && state->ipv6_frag_state)) {
    pfwl_reordering_ipv6_fragmentation_set_total_memory_limit(
        state->ipv6_frag_state, total_memory_limit);
    return 1;
  } else {
    return 0;
  }
}

uint8_t pfwl_ipv4_fragmentation_set_reassembly_timeout(
    pfwl_state_t* state, uint8_t timeout_seconds) {
  if (likely(state && state->ipv4_frag_state)) {
    pfwl_reordering_ipv4_fragmentation_set_reassembly_timeout(
        state->ipv4_frag_state, timeout_seconds);
    return 1;
  } else {
    return 0;
  }
}

uint8_t pfwl_ipv6_fragmentation_set_reassembly_timeout(
    pfwl_state_t* state, uint8_t timeout_seconds) {
  if (likely(state && state->ipv6_frag_state)) {
    pfwl_reordering_ipv6_fragmentation_set_reassembly_timeout(
        state->ipv6_frag_state, timeout_seconds);
    return 1;
  } else {
    return 0;
  }
}

uint8_t pfwl_ipv4_fragmentation_disable(pfwl_state_t* state) {
  if (likely(state && state->ipv4_frag_state)) {
    pfwl_reordering_disable_ipv4_fragmentation(state->ipv4_frag_state);
    state->ipv4_frag_state = NULL;
    return 1;
  } else {
    return 0;
  }
}

uint8_t pfwl_ipv6_fragmentation_disable(pfwl_state_t* state) {
  if (likely(state && state->ipv6_frag_state)) {
    pfwl_reordering_disable_ipv6_fragmentation(state->ipv6_frag_state);
    state->ipv6_frag_state = NULL;
    return 1;
  } else {
    return 0;
  }
}

uint8_t pfwl_tcp_reordering_enable(pfwl_state_t* state) {
  if (likely(state)) {
    state->tcp_reordering_enabled = 1;
    return 1;
  } else {
    return 0;
  }
}

uint8_t pfwl_tcp_reordering_disable(pfwl_state_t* state) {
  if (likely(state)) {
    state->tcp_reordering_enabled = 0;
    return 1;
  } else {
    return 0;
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
    return 1;
  } else {
    return 0;
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
    BITCLEAR(state->active_callbacks, protocol);
    return 1;
  } else {
    return 1;
  }
}

uint8_t pfwl_inspect_all(pfwl_state_t* state) {
  unsigned char nonzero = ~0;
  memset(state->protocols_to_inspect, nonzero, BITNSLOTS(PFWL_NUM_PROTOCOLS));
  state->active_protocols = PFWL_NUM_PROTOCOLS;
  return 1;
}

uint8_t pfwl_inspect_nothing(pfwl_state_t* state) {
  bzero(state->protocols_to_inspect, BITNSLOTS(PFWL_NUM_PROTOCOLS));

  state->active_protocols = 0;

  bzero(state->active_callbacks, PFWL_NUM_PROTOCOLS);
  return 1;
}

uint8_t pfwl_skip_L7_parsing_by_port(pfwl_state_t* state, uint8_t l4prot,
                                    uint16_t port, pfwl_protocol_l7_t id) {
  pfwl_l7_skipping_info_t* skinfo = malloc(sizeof(pfwl_l7_skipping_info_t));
  memset(skinfo, 0, sizeof(pfwl_l7_skipping_info_t));
  skinfo->key.l4prot = l4prot;
  skinfo->key.port = port;
  skinfo->protocol = id;
  HASH_ADD(hh, state->l7_skip, key, sizeof(skinfo->key), skinfo);
  return 1;
}

void pfwl_terminate(pfwl_state_t* state) {
  if (likely(state)) {
    pfwl_ipv4_fragmentation_disable(state);
    pfwl_ipv6_fragmentation_disable(state);
    pfwl_tcp_reordering_disable(state);

    pfwl_flow_table_delete(state->flow_table, state->flow_cleaner_callback);
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
  uint8_t l3_status;

  r = pfwl_parse_L3_L4(state, pkt, length, current_time);
  l3_status = r.status;

  if (unlikely(r.status == PFWL_STATUS_IP_FRAGMENT || r.status < 0)) {
    return r;
  }

  uint8_t skip_l7 = 0;
  uint16_t srcport = ntohs(r.port_src);
  uint16_t dstport = ntohs(r.port_dst);
  pfwl_l7_skipping_info_t* sk = NULL;
  pfwl_l7_skipping_info_key_t key;
  memset(&key, 0, sizeof(key));
  key.l4prot = r.protocol_l4;
  key.port = dstport;
  HASH_FIND(hh, state->l7_skip, &key, sizeof(pfwl_l7_skipping_info_key_t), sk);
  if (sk) {
    skip_l7 = 1;
    r.protocol_l7 = sk->protocol;
  } else {
    key.port = srcport;
    HASH_FIND(hh, state->l7_skip, &key, sizeof(pfwl_l7_skipping_info_key_t),
              sk);
    if (sk) {
      skip_l7 = 1;
      r.protocol_l7 = sk->protocol;
    }
  }

  if (!skip_l7) {
    if (r.protocol_l4 != IPPROTO_TCP && r.protocol_l4 != IPPROTO_UDP) {
      return r;
    }

    r.status = PFWL_STATUS_OK;
    /**
     * We return the status of pfwl_stateful_get_app_protocol call,
     * without giving informations on status returned
     * by pfwl_parse_L3_L4_headers. Basically we return the status which
     * provides more informations.
     */
    pfwl_parse_L7(state, &r);
  }

  if (l3_status == PFWL_STATUS_IP_LAST_FRAGMENT) {
    free((unsigned char*) r.pkt);
  }

  return r;
}

pfwl_identification_result_t mc_pfwl_parse_L3_L4_header(pfwl_state_t* state,
                                   const unsigned char* p_pkt,
                                   uint32_t p_length,
                                   uint32_t current_time, int tid) {
  pfwl_identification_result_t r;
  memset(&r, 0, sizeof(r));
  r.status = PFWL_STATUS_OK;
  if (unlikely(p_length == 0)) return r;
  uint8_t version;
#if __BYTE_ORDER == __LITTLE_ENDIAN
  version = (p_pkt[0] >> 4) & 0x0F;
#elif __BYTE_ORDER == __BIG_ENDIAN
  version = (p_pkt[0] << 4) & 0x0F;
#else
#error "Please fix <bits/endian.h>"
#endif

  unsigned char* pkt = (unsigned char*) p_pkt;
  uint32_t length = p_length;
  uint16_t offset;
  uint8_t more_fragments;

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
      r.status = PFWL_ERROR_L3_TRUNCATED_PACKET;
      return r;
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

    /*
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
        r.status = PFWL_STATUS_IP_FRAGMENT;
        return r;
      }
      to_return = PFWL_STATUS_IP_LAST_FRAGMENT;
      ip4 = (struct iphdr*)(pkt);
      length = ntohs(((struct iphdr*)(pkt))->tot_len);
    } else {
      r.status = PFWL_STATUS_IP_FRAGMENT;
      return r;
    }

    r.addr_src.ipv4 = ip4->saddr;
    r.addr_dst.ipv4 = ip4->daddr;

    application_offset = (ip4->ihl) * 4;
    relative_offset = application_offset;

    next_header = ip4->protocol;
  } else if (version == PFWL_IP_VERSION_6) { /** IPv6 **/
    ip6 = (struct ip6_hdr*)(pkt);
    uint16_t tot_len =
        ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) + sizeof(struct ip6_hdr);
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
    if (unlikely(tot_len > length)) {
      r.status = PFWL_ERROR_L3_TRUNCATED_PACKET;
      return r;
    }
#endif

    /**
     * At this point we are sure that tot_len<=length, so we set
     * length=tot_len. In some cases indeed there may be an L2 padding
     * at the end of the packet, so capture length (length) may be
     * greater than the effective datagram length.
     */
    length = tot_len;

    r.addr_src.ipv6 = ip6->ip6_src;
    r.addr_dst.ipv6 = ip6->ip6_dst;

    application_offset = sizeof(struct ip6_hdr);
    relative_offset = application_offset;
    next_header = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
  } else {
    r.status = PFWL_ERROR_WRONG_IPVERSION;
    return r;
  }

  while (!stop) {
    switch (next_header) {
      case IPPROTO_TCP: { /* TCP */
        struct tcphdr* tcp = (struct tcphdr*)(pkt + application_offset);
#ifdef PFWL_ENABLE_L4_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct tcphdr) > length ||
                     application_offset + tcp->doff * 4 > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          r.status = PFWL_ERROR_L4_TRUNCATED_PACKET;
          return r;
        }
#endif
        r.port_src = tcp->source;
        r.port_dst = tcp->dest;
        r.offset_l4 = application_offset;
        application_offset += (tcp->doff * 4);
        stop = 1;
      } break;
      case IPPROTO_UDP: { /* UDP */
        struct udphdr* udp = (struct udphdr*)(pkt + application_offset);
#ifdef PFWL_ENABLE_L4_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct udphdr) > length ||
                     application_offset + ntohs(udp->len) > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          r.status = PFWL_ERROR_L4_TRUNCATED_PACKET;
          return r;
        }
#endif
        r.port_src = udp->source;
        r.port_dst = udp->dest;
        r.offset_l4 = application_offset;
        application_offset += 8;
        stop = 1;
      } break;
      case IPPROTO_HOPOPTS: { /* Hop by hop options */
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct ip6_hbh) > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          r.status = PFWL_ERROR_L3_TRUNCATED_PACKET;
          return r;
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
          r.status = PFWL_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
          return r;
        }
      } break;
      case IPPROTO_DSTOPTS: { /* Destination options */
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct ip6_dest) > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          r.status = PFWL_ERROR_L3_TRUNCATED_PACKET;
          return r;
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
          r.status = PFWL_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
          return r;
        }
      } break;
      case IPPROTO_ROUTING: { /* Routing header */
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct ip6_rthdr) > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          r.status = PFWL_ERROR_L3_TRUNCATED_PACKET;
          return r;
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
          r.status = PFWL_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
          return r;
        }
      } break;
      case IPPROTO_FRAGMENT: { /* Fragment header */
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct ip6_frag) > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          r.status = PFWL_ERROR_L3_TRUNCATED_PACKET;
          return r;
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

            /*
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
              r.status = PFWL_STATUS_IP_FRAGMENT;
              return r;
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
            r.status = PFWL_STATUS_IP_FRAGMENT;
            return r;
          }
        } else {
          if (unlikely(pkt != p_pkt)) free(pkt);
          r.status = PFWL_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
          return r;
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
          r.status = PFWL_ERROR_L3_TRUNCATED_PACKET;
          return r;
        }
#endif

        r.addr_src.ipv6 = ip6->ip6_src;
        r.addr_dst.ipv6 = ip6->ip6_dst;

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
          r.status = PFWL_ERROR_L3_TRUNCATED_PACKET;
          return r;
        }
#endif
        r.addr_src.ipv4 = ip4->saddr;
        r.addr_dst.ipv4 = ip4->daddr;
        next_header = ip4->protocol;
        tmp = (ip4->ihl) * 4;
        application_offset += tmp;
        relative_offset = tmp;
        break;
      default:
        stop = 1;
        r.offset_l4 = application_offset;
        break;
    }
  }

  r.protocol_l4 = next_header;
#ifdef PFWL_ENABLE_L4_TRUNCATION_PROTECTION
  if (unlikely(application_offset > length)) {
    if (unlikely(pkt != p_pkt)) free(pkt);
    r.status = PFWL_ERROR_L4_TRUNCATED_PACKET;
    return r;
  }
#endif
  r.timestamp = current_time;
  r.pkt = pkt;
  r.offset_l7 = application_offset;
  r.data_length_l7 = length - application_offset;
  r.ip_version = version;
  r.status = to_return;
  return r;
}

pfwl_identification_result_t pfwl_parse_L3_L4(pfwl_state_t* state,
                                const unsigned char* p_pkt, uint32_t p_length,
                                uint32_t current_time) {
  /**
   * We can pass any thread id, indeed in this case we don't
   * need lock synchronization.
   **/
  return mc_pfwl_parse_L3_L4_header(state, p_pkt, p_length, current_time, 0);
}

void pfwl_parse_L7(pfwl_state_t* state, pfwl_identification_result_t *identification_info) {
  identification_info->status = PFWL_STATUS_OK;

  pfwl_flow_info_t* flow_info = NULL;
  pfwl_flow_t* flow = NULL;

  flow = pfwl_flow_table_find_or_create_flow(state->flow_table, identification_info, state->flow_cleaner_callback,
                                             state->protocols_to_inspect, state->tcp_reordering_enabled);

  if (unlikely(flow == NULL)) {
    identification_info->status = PFWL_ERROR_MAX_FLOWS;
    return;
  }

  flow_info = &(flow->info);

  pfwl_parse_L7_stateless(state, identification_info, flow_info);

  if (identification_info->status == PFWL_STATUS_TCP_CONNECTION_TERMINATED) {
    pfwl_flow_table_delete_flow(state->flow_table, state->flow_cleaner_callback, flow);
  }
  return;
}

void pfwl_parse_L7_stateless(pfwl_state_t* state, pfwl_identification_result_t *identification_info, pfwl_flow_info_t* flow) {
  identification_info->status = PFWL_STATUS_OK;
  identification_info->user_flow_data = (flow->tracking.udata);
  pfwl_protocol_l7_t i;

  uint8_t check_result = PFWL_PROTOCOL_NO_MATCHES;
  const pfwl_protocol_l7_t* well_known_ports;
  const unsigned char* app_data = identification_info->pkt + identification_info->offset_l7;
  uint32_t data_length = identification_info->data_length_l7;
  pfwl_tcp_reordering_reordered_segment_t seg;
  seg.status = PFWL_TCP_REORDERING_STATUS_IN_ORDER;
  seg.data = NULL;
  seg.connection_terminated = 0;

  if(data_length){
    ++flow->tracking.num_packets;
  }

  if (flow->l7prot < PFWL_PROTOCOL_NOT_DETERMINED) {
    identification_info->protocol_l7 = flow->l7prot;
    if (identification_info->protocol_l4 == IPPROTO_TCP) {
      if (flow->tcp_reordering_enabled) {
        seg = pfwl_reordering_tcp_track_connection(identification_info, &(flow->tracking));

        if (seg.status == PFWL_TCP_REORDERING_STATUS_OUT_OF_ORDER) {
          identification_info->status = PFWL_STATUS_TCP_OUT_OF_ORDER;
          return;
        } else if (seg.status == PFWL_TCP_REORDERING_STATUS_REBUILT) {
          app_data = seg.data;
          data_length = seg.data_length;
          if(flow->last_rebuilt_tcp_data){
            free((void*) flow->last_rebuilt_tcp_data);
          }
          flow->last_rebuilt_tcp_data = app_data;
        }
      } else {
        seg.connection_terminated = pfwl_reordering_tcp_track_connection_light(identification_info, &(flow->tracking));
      }
    }

    pfwl_tracking_informations_t* t = &(flow->tracking);
    if (flow->l7prot < PFWL_NUM_PROTOCOLS &&
        state->fields_extraction[flow->l7prot].fields_num) {
      pfwl_protocol_descriptor_t descr = protocols_descriptors[flow->l7prot];
      (*(descr.dissector))(app_data, data_length, identification_info, t, state->inspectors_accuracy[flow->l7prot], state->fields_extraction[flow->l7prot].fields);
    }

    if (seg.connection_terminated) {
      identification_info->status = PFWL_STATUS_TCP_CONNECTION_TERMINATED;
    }
    return;
  } else if (flow->l7prot == PFWL_PROTOCOL_NOT_DETERMINED) {
    if (identification_info->protocol_l4 == IPPROTO_TCP && state->active_protocols > 0) {
      well_known_ports = pfwl_well_known_ports_association_tcp;
      if (flow->tcp_reordering_enabled) {
        seg = pfwl_reordering_tcp_track_connection(identification_info, &(flow->tracking));

        if (seg.status == PFWL_TCP_REORDERING_STATUS_OUT_OF_ORDER) {
          identification_info->status = PFWL_STATUS_TCP_OUT_OF_ORDER;
          identification_info->protocol_l7 = PFWL_PROTOCOL_UNKNOWN;
          return;
        } else if (seg.status == PFWL_TCP_REORDERING_STATUS_REBUILT) {
          app_data = seg.data;
          data_length = seg.data_length;
          if(flow->last_rebuilt_tcp_data){
            free((void*) flow->last_rebuilt_tcp_data);
          }
          flow->last_rebuilt_tcp_data = app_data;
        }
      } else {
        if (pfwl_reordering_tcp_track_connection_light(identification_info, &(flow->tracking)))
          identification_info->status = PFWL_STATUS_TCP_CONNECTION_TERMINATED;
      }
    } else if (identification_info->protocol_l4 == IPPROTO_UDP &&
               state->active_protocols > 0) {
      well_known_ports = pfwl_well_known_ports_association_udp;
    } else {
      return;
    }

    /**
     * If we have no payload we don't do anything. We already
     * invoked the TCP reordering to update the connection state.
     */
    if (data_length == 0) {
      identification_info->protocol_l7 = flow->l7prot;
      return;
    }

    pfwl_protocol_l7_t first_protocol_to_check;
    pfwl_protocol_l7_t checked_protocols = 0;

    if ((first_protocol_to_check = well_known_ports[identification_info->port_src]) ==
            PFWL_PROTOCOL_UNKNOWN &&
        (first_protocol_to_check = well_known_ports[identification_info->port_dst]) ==
            PFWL_PROTOCOL_UNKNOWN) {
      first_protocol_to_check = 0;
    }

    for (i = first_protocol_to_check; checked_protocols < PFWL_NUM_PROTOCOLS;
         i = (i + 1) % PFWL_NUM_PROTOCOLS, ++checked_protocols) {
      if (BITTEST(flow->possible_matching_protocols, i)) {
        pfwl_protocol_descriptor_t descr = protocols_descriptors[i];
        pfwl_tracking_informations_t* t = &(flow->tracking);
        check_result = (*(descr.dissector))(app_data, data_length, identification_info, t, state->inspectors_accuracy[i], state->fields_extraction[i].fields);
        if (check_result == PFWL_PROTOCOL_MATCHES) {
          flow->l7prot = i;
          identification_info->protocol_l7 = flow->l7prot;

          if (seg.connection_terminated) {
            identification_info->status = PFWL_STATUS_TCP_CONNECTION_TERMINATED;
          }
          return;
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

  identification_info->protocol_l7 = flow->l7prot;

  if(flow->last_rebuilt_tcp_data){
    free((void*) flow->last_rebuilt_tcp_data);
    flow->last_rebuilt_tcp_data = NULL;
  }

  if (seg.connection_terminated) {
    identification_info->status = PFWL_STATUS_TCP_CONNECTION_TERMINATED;
  }
  return;
}

pfwl_protocol_l7_t pfwl_guess_protocol(pfwl_identification_result_t identification_info) {
  pfwl_protocol_l7_t r = PFWL_PROTOCOL_UNKNOWN;
  if (identification_info.protocol_l4 == IPPROTO_TCP) {
    r = pfwl_well_known_ports_association_tcp[identification_info.port_src];
    if (r == PFWL_PROTOCOL_UNKNOWN)
      r = pfwl_well_known_ports_association_tcp[identification_info.port_dst];
  } else if (identification_info.protocol_l4 == IPPROTO_UDP) {
    r = pfwl_well_known_ports_association_udp[identification_info.port_src];
    if (r == PFWL_PROTOCOL_UNKNOWN)
      r = pfwl_well_known_ports_association_udp[identification_info.port_dst];
  } else {
    r = PFWL_PROTOCOL_UNKNOWN;
  }
  return r;
}

uint8_t pfwl_set_protocol_accuracy(pfwl_state_t *state,
                                  pfwl_protocol_l7_t protocol,
                                  pfwl_inspector_accuracy_t accuracy) {
  if (state) {
    state->inspectors_accuracy[protocol] = accuracy;
    return 1;
  } else {
    return 0;
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

const char* const pfwl_get_protocol_string(pfwl_protocol_l7_t protocol) {
  if (protocol < PFWL_NUM_PROTOCOLS) {
    return protocols_descriptors[protocol].name;
  } else {
    return "Unknown";
  }
}

pfwl_protocol_l7_t pfwl_get_protocol_id(const char* const string) {
  size_t i;
  for (i = 0; i < (size_t)PFWL_NUM_PROTOCOLS; i++) {
    if (strcasecmp(string, protocols_descriptors[i].name) == 0) {
      return (pfwl_protocol_l7_t)i;
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
                                       pfwl_flow_cleaner_callback_t* cleaner) {
  state->flow_cleaner_callback = cleaner;
  return 1;
}

uint8_t pfwl_protocol_field_add(pfwl_state_t* state,
                                 pfwl_protocol_l7_t protocol,
                                 int field_type){
  if(state){
    state->fields_extraction[protocol].fields[field_type] = 1;
    state->fields_extraction[protocol].fields_num++;
    pfwl_set_protocol_accuracy(state, protocol, PFWL_INSPECTOR_ACCURACY_HIGH);  // TODO: mmm, the problem is that we do not set back the original accuracy when doing field_remove
    return 1;
  }else{
    return 0;
  }
}

uint8_t pfwl_protocol_field_remove(pfwl_state_t* state,
                                    pfwl_protocol_l7_t protocol,
                                    int field_type){
  if(state){
    state->fields_extraction[protocol].fields[field_type] = 0;
    state->fields_extraction[protocol].fields_num--;
    return 1;
  }else{
    return 0;
  }
}

uint8_t pfwl_protocol_field_required(pfwl_state_t* state,
                                      pfwl_protocol_l7_t protocol,
                                      int field_type){
  if(state){
    return state->fields_extraction[protocol].fields[field_type];
  }else{
    return 0;
  }
}

uint8_t pfwl_callbacks_fields_set_udata(pfwl_state_t* state,
                                        void* udata){
    if(state){
        state->callbacks_udata = udata;
        return 1;
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
