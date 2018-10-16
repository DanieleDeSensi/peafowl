/*
 * peafowl_l7_parsing.c
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

#define debug_print(fmt, ...)                                                  \
  do {                                                                         \
    if (PFWL_DEBUG)                                                            \
      fprintf(stderr, fmt, __VA_ARGS__);                                       \
  } while (0)

// clang-format off
static const pfwl_protocol_l7_t pfwl_known_ports_tcp[PFWL_MAX_UINT_16 + 1] = {
        [0 ... PFWL_MAX_UINT_16] = PFWL_PROTO_L7_UNKNOWN, 
        [port_dns] = PFWL_PROTO_L7_DNS, 
        [port_http] = PFWL_PROTO_L7_HTTP, 
        [port_bgp] = PFWL_PROTO_L7_BGP, 
        [port_smtp_1] = PFWL_PROTO_L7_SMTP, 
        [port_smtp_2] = PFWL_PROTO_L7_SMTP, 
        [port_smtp_ssl] = PFWL_PROTO_L7_SMTP, 
        [port_pop3] = PFWL_PROTO_L7_POP3, 
        [port_pop3_ssl] = PFWL_PROTO_L7_POP3, 
        [port_imap] = PFWL_PROTO_L7_IMAP, 
        [port_imap_ssl] = PFWL_PROTO_L7_IMAP, 
        [port_ssl] = PFWL_PROTO_L7_SSL, 
        [port_hangout_19305] = PFWL_PROTO_L7_HANGOUT, 
        [port_hangout_19306] = PFWL_PROTO_L7_HANGOUT, 
        [port_hangout_19307] = PFWL_PROTO_L7_HANGOUT, 
        [port_hangout_19308] = PFWL_PROTO_L7_HANGOUT, 
        [port_hangout_19309] = PFWL_PROTO_L7_HANGOUT, 
        [port_ssh] = PFWL_PROTO_L7_SSH,
        [port_bitcoin] = PFWL_PROTO_L7_BITCOIN,
};

static const pfwl_protocol_l7_t pfwl_known_ports_udp[PFWL_MAX_UINT_16 + 1] = {
        [0 ... PFWL_MAX_UINT_16] = PFWL_PROTO_L7_UNKNOWN, 
        [port_dns] = PFWL_PROTO_L7_DNS, 
        [port_mdns] = PFWL_PROTO_L7_MDNS, 
        [port_dhcp_1] = PFWL_PROTO_L7_DHCP, 
        [port_dhcp_2] = PFWL_PROTO_L7_DHCP, 
        [port_dhcpv6_1] = PFWL_PROTO_L7_DHCPv6, 
        [port_dhcpv6_2] = PFWL_PROTO_L7_DHCPv6, 
        [port_sip] = PFWL_PROTO_L7_SIP, 
        [port_ntp] = PFWL_PROTO_L7_NTP, 
        [port_hangout_19302] = PFWL_PROTO_L7_HANGOUT, 
        [port_hangout_19303] = PFWL_PROTO_L7_HANGOUT, 
        [port_hangout_19304] = PFWL_PROTO_L7_HANGOUT, 
        [port_hangout_19305] = PFWL_PROTO_L7_HANGOUT, 
        [port_hangout_19306] = PFWL_PROTO_L7_HANGOUT, 
        [port_hangout_19307] = PFWL_PROTO_L7_HANGOUT, 
        [port_hangout_19308] = PFWL_PROTO_L7_HANGOUT, 
        [port_hangout_19309] = PFWL_PROTO_L7_HANGOUT, 
        [port_dropbox] = PFWL_PROTO_L7_DROPBOX, 
        [port_spotify] = PFWL_PROTO_L7_SPOTIFY,
};
// clang-format on

typedef enum {
  PFWL_L7_TRANSPORT_TCP = 0,
  PFWL_L7_TRANSPORT_UDP,
  PFWL_L7_TRANSPORT_TCP_OR_UDP,
} pfwl_l7_transport_t;

typedef struct {
  const char *name;
  pfwl_dissector dissector;
  pfwl_l7_transport_t transport;
} pfwl_protocol_descriptor_t;

// clang-format off
static const pfwl_protocol_descriptor_t protocols_descriptors[PFWL_PROTO_L7_NUM] = {
        [PFWL_PROTO_L7_DHCP]     = {"DHCP"    , check_dhcp    , PFWL_L7_TRANSPORT_UDP},
        [PFWL_PROTO_L7_DHCPv6]   = {"DHCPv6"  , check_dhcpv6  , PFWL_L7_TRANSPORT_UDP},
        [PFWL_PROTO_L7_DNS]      = {"DNS"     , check_dns     , PFWL_L7_TRANSPORT_TCP_OR_UDP},
        [PFWL_PROTO_L7_MDNS]     = {"MDNS"    , check_mdns    , PFWL_L7_TRANSPORT_UDP},
        [PFWL_PROTO_L7_SIP]      = {"SIP"     , check_sip     , PFWL_L7_TRANSPORT_TCP_OR_UDP},
        [PFWL_PROTO_L7_RTP]      = {"RTP"     , check_rtp     , PFWL_L7_TRANSPORT_UDP},
        [PFWL_PROTO_L7_RTCP]     = {"RTCP"    , check_rtcp    , PFWL_L7_TRANSPORT_UDP},
        [PFWL_PROTO_L7_SSH]      = {"SSH"     , check_ssh     , PFWL_L7_TRANSPORT_TCP},
        [PFWL_PROTO_L7_SKYPE]    = {"Skype"   , check_skype   , PFWL_L7_TRANSPORT_UDP},
        [PFWL_PROTO_L7_NTP]      = {"NTP"     , check_ntp     , PFWL_L7_TRANSPORT_UDP},
        [PFWL_PROTO_L7_BGP]      = {"BGP"     , check_bgp     , PFWL_L7_TRANSPORT_TCP},
        [PFWL_PROTO_L7_HTTP]     = {"HTTP"    , check_http    , PFWL_L7_TRANSPORT_TCP},
        [PFWL_PROTO_L7_SMTP]     = {"SMTP"    , check_smtp    , PFWL_L7_TRANSPORT_TCP},
        [PFWL_PROTO_L7_POP3]     = {"POP3"    , check_pop3    , PFWL_L7_TRANSPORT_TCP},
        [PFWL_PROTO_L7_IMAP]     = {"IMAP"    , check_imap    , PFWL_L7_TRANSPORT_TCP},
        [PFWL_PROTO_L7_SSL]      = {"SSL"     , check_ssl     , PFWL_L7_TRANSPORT_TCP},
        [PFWL_PROTO_L7_HANGOUT]  = {"Hangout" , check_hangout , PFWL_L7_TRANSPORT_TCP_OR_UDP},
        [PFWL_PROTO_L7_WHATSAPP] = {"WhatsApp", check_whatsapp, PFWL_L7_TRANSPORT_TCP},
        [PFWL_PROTO_L7_TELEGRAM] = {"Telegram", check_telegram, PFWL_L7_TRANSPORT_TCP},
        [PFWL_PROTO_L7_DROPBOX]  = {"Dropbox" , check_dropbox , PFWL_L7_TRANSPORT_UDP},
        [PFWL_PROTO_L7_SPOTIFY]  = {"Spotify" , check_spotify , PFWL_L7_TRANSPORT_TCP_OR_UDP},
        [PFWL_PROTO_L7_BITCOIN]  = {"Bitcoin" , check_bitcoin , PFWL_L7_TRANSPORT_TCP},
        [PFWL_PROTO_L7_ETHEREUM] = {"Ethereum", check_ethereum, PFWL_L7_TRANSPORT_TCP},
        [PFWL_PROTO_L7_ZCASH]    = {"Zcash"   , check_zcash   , PFWL_L7_TRANSPORT_TCP},
        [PFWL_PROTO_L7_MONERO]   = {"Monero"  , check_monero  , PFWL_L7_TRANSPORT_TCP},
};
// clang-format on

static int inspect_protocol(pfwl_protocol_l4_t protocol_l4,
                            const pfwl_protocol_descriptor_t *descr) {
  return descr->transport == PFWL_L7_TRANSPORT_TCP_OR_UDP ||
         (protocol_l4 == IPPROTO_TCP &&
          descr->transport == PFWL_L7_TRANSPORT_TCP) ||
         (protocol_l4 == IPPROTO_UDP &&
          descr->transport == PFWL_L7_TRANSPORT_UDP);
}

pfwl_status_t pfwl_dissect_L7(pfwl_state_t *state, const unsigned char *pkt,
                              size_t length, pfwl_dissection_info_t *diss_info,
                              pfwl_flow_info_private_t *flow_info_private) {
  pfwl_protocol_l7_t i;
  uint8_t check_result = PFWL_PROTOCOL_NO_MATCHES;
  const pfwl_protocol_l7_t *well_known_ports;

  ++((pfwl_flow_info_t *) flow_info_private->info_public)
        ->num_packets_l7[diss_info->l4.direction];
  ((pfwl_flow_info_t *) flow_info_private->info_public)
      ->num_bytes_l7[diss_info->l4.direction] += length;

  if ((diss_info->l4.protocol == IPPROTO_TCP && !state->active_protocols[0]) ||
      (diss_info->l4.protocol == IPPROTO_UDP && !state->active_protocols[1])) {
    return PFWL_STATUS_OK;
  }

  diss_info->flow_info.num_packets_l7[diss_info->l4.direction] =
      flow_info_private->info_public->num_packets_l7[diss_info->l4.direction];
  diss_info->flow_info.num_bytes_l7[diss_info->l4.direction] =
      flow_info_private->info_public->num_bytes_l7[diss_info->l4.direction];

  if (flow_info_private->l7prot < PFWL_PROTO_L7_NUM) {
    if (state->fields_to_extract_num[flow_info_private->l7prot]) {
      pfwl_protocol_descriptor_t descr =
          protocols_descriptors[flow_info_private->l7prot];
      (*(descr.dissector))(state, pkt, length, diss_info, flow_info_private);
    }
    return PFWL_STATUS_OK;
  } else if (flow_info_private->l7prot == PFWL_PROTO_L7_NOT_DETERMINED) {
    if (diss_info->l4.protocol == IPPROTO_TCP) {
      well_known_ports = pfwl_known_ports_tcp;
    } else if (diss_info->l4.protocol == IPPROTO_UDP) {
      well_known_ports = pfwl_known_ports_udp;
    } else {
      return PFWL_STATUS_OK;
    }

    pfwl_protocol_l7_t first_to_check;
    pfwl_protocol_l7_t checked = 0;

    if ((first_to_check = well_known_ports[diss_info->l4.port_src]) ==
            PFWL_PROTO_L7_UNKNOWN &&
        (first_to_check = well_known_ports[diss_info->l4.port_dst]) ==
            PFWL_PROTO_L7_UNKNOWN) {
      first_to_check = 0;
    }

    for (i = first_to_check; checked < PFWL_PROTO_L7_NUM;
         i = (i + 1) % PFWL_PROTO_L7_NUM, ++checked) {
      if (BITTEST(flow_info_private->possible_matching_protocols, i)) {
        pfwl_protocol_descriptor_t descr = protocols_descriptors[i];
        if (inspect_protocol(diss_info->l4.protocol, &descr)) {
          check_result = (*(descr.dissector))(state, pkt, length, diss_info,
                                              flow_info_private);
          if (check_result == PFWL_PROTOCOL_MATCHES) {
            flow_info_private->l7prot = i;
            diss_info->l7.protocol = flow_info_private->l7prot;
            return PFWL_STATUS_OK;
          } else if (check_result == PFWL_PROTOCOL_NO_MATCHES) {
            BITCLEAR(flow_info_private->possible_matching_protocols, i);
            --(flow_info_private->possible_protocols);
          }
        } else {
          BITCLEAR(flow_info_private->possible_matching_protocols, i);
          --(flow_info_private->possible_protocols);
        }
      }
    }

    /**
     * If all the protocols don't match or if we still have
     * ambiguity after the maximum number of trials, then the
     * library was unable to identify the protocol.
     **/
    if (flow_info_private->possible_protocols == 0 ||
        (state->max_trials != 0 &&
         unlikely(++flow_info_private->trials == state->max_trials))) {
      flow_info_private->l7prot = PFWL_PROTO_L7_UNKNOWN;
    }
  }

  diss_info->l7.protocol = flow_info_private->l7prot;

  return PFWL_STATUS_OK;
}

pfwl_protocol_l7_t
pfwl_guess_protocol(pfwl_dissection_info_t identification_info) {
  pfwl_protocol_l7_t r = PFWL_PROTO_L7_UNKNOWN;
  if (identification_info.l4.protocol == IPPROTO_TCP) {
    r = pfwl_known_ports_tcp[identification_info.l4.port_src];
    if (r == PFWL_PROTO_L7_UNKNOWN)
      r = pfwl_known_ports_tcp[identification_info.l4.port_dst];
  } else if (identification_info.l4.protocol == IPPROTO_UDP) {
    r = pfwl_known_ports_udp[identification_info.l4.port_src];
    if (r == PFWL_PROTO_L7_UNKNOWN)
      r = pfwl_known_ports_udp[identification_info.l4.port_dst];
  } else {
    r = PFWL_PROTO_L7_UNKNOWN;
  }
  return r;
}

const char *pfwl_get_L7_protocol_name(pfwl_protocol_l7_t protocol) {
  if (protocol < PFWL_PROTO_L7_NUM) {
    return protocols_descriptors[protocol].name;
  } else {
    return "Unknown";
  }
}

pfwl_protocol_l7_t pfwl_get_L7_protocol_id(const char *const string) {
  size_t i;
  for (i = 0; i < (size_t) PFWL_PROTO_L7_NUM; i++) {
    if (!strcasecmp(string, protocols_descriptors[i].name)) {
      return (pfwl_protocol_l7_t) i;
    }
  }
  return PFWL_PROTO_L7_NUM;
}

static const char *protocols_strings[PFWL_PROTO_L7_NUM];

const char **const pfwl_get_L7_protocols_names() {
  size_t i;
  for (i = 0; i < (size_t) PFWL_PROTO_L7_NUM; i++) {
    protocols_strings[i] = protocols_descriptors[i].name;
  }
  return protocols_strings;
}

uint8_t pfwl_protocol_l7_enable(pfwl_state_t *state,
                                pfwl_protocol_l7_t protocol) {
  if (protocol < PFWL_PROTO_L7_NUM) {
    // Increment counter only if it was not set, otherwise
    // calling twice enable_protocol on the same protocol
    // would lead to a wrong number of active protocols
    if (!BITTEST(state->protocols_to_inspect, protocol)) {
      if (protocols_descriptors[protocol].transport == PFWL_L7_TRANSPORT_TCP ||
          protocols_descriptors[protocol].transport ==
              PFWL_L7_TRANSPORT_TCP_OR_UDP) {
        ++state->active_protocols[0];
      }
      if (protocols_descriptors[protocol].transport == PFWL_L7_TRANSPORT_UDP ||
          protocols_descriptors[protocol].transport ==
              PFWL_L7_TRANSPORT_TCP_OR_UDP) {
        ++state->active_protocols[1];
      }
    }
    BITSET(state->protocols_to_inspect, protocol);
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_protocol_l7_disable(pfwl_state_t *state,
                                 pfwl_protocol_l7_t protocol) {
  if (protocol < PFWL_PROTO_L7_NUM) {
    // Decrement counter only if it was set, otherwise
    // calling twice disable_protocol on the same protocol
    // would lead to a wrong number of active protocols
    if (BITTEST(state->protocols_to_inspect, protocol)) {
      if (protocols_descriptors[protocol].transport == PFWL_L7_TRANSPORT_TCP ||
          protocols_descriptors[protocol].transport ==
              PFWL_L7_TRANSPORT_TCP_OR_UDP) {
        --state->active_protocols[0];
      }
      if (protocols_descriptors[protocol].transport == PFWL_L7_TRANSPORT_UDP ||
          protocols_descriptors[protocol].transport ==
              PFWL_L7_TRANSPORT_TCP_OR_UDP) {
        --state->active_protocols[1];
      }
    }
    BITCLEAR(state->protocols_to_inspect, protocol);
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_protocol_l7_enable_all(pfwl_state_t *state) {
  for (size_t i = 0; i < PFWL_PROTO_L7_NUM; i++) {
    if (pfwl_protocol_l7_enable(state, i)) {
      return 1;
    }
  }
  return 0;
}

uint8_t pfwl_protocol_l7_disable_all(pfwl_state_t *state) {
  for (size_t i = 0; i < PFWL_PROTO_L7_NUM; i++) {
    if (pfwl_protocol_l7_disable(state, i)) {
      return 1;
    }
  }
  return 0;
}
