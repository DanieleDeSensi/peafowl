/*
 * peafowl_l7_parsing.c
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
}pfwl_protocol_descriptor_t;

static const pfwl_protocol_descriptor_t const protocols_descriptors[PFWL_NUM_PROTOCOLS] =
  {
    [PFWL_PROTOCOL_DHCP]     = {"DHCP"    , check_dhcp    },
    [PFWL_PROTOCOL_DHCPv6]   = {"DHCPv6"  , check_dhcpv6  },
    [PFWL_PROTOCOL_DNS]      = {"DNS"     , check_dns     },
    [PFWL_PROTOCOL_MDNS]     = {"MDNS"    , check_mdns    },
    [PFWL_PROTOCOL_SIP]      = {"SIP"     , check_sip     },
    [PFWL_PROTOCOL_RTP]      = {"RTP"     , check_rtp     },
    [PFWL_PROTOCOL_SSH]      = {"SSH"     , check_ssh     },
    [PFWL_PROTOCOL_SKYPE]    = {"Skype"   , check_skype   },
    [PFWL_PROTOCOL_NTP]      = {"NTP"     , check_ntp     },
    [PFWL_PROTOCOL_BGP]      = {"BGP"     , check_bgp     },
    [PFWL_PROTOCOL_HTTP]     = {"HTTP"    , check_http    },
    [PFWL_PROTOCOL_SMTP]     = {"SMTP"    , check_smtp    },
    [PFWL_PROTOCOL_POP3]     = {"POP3"    , check_pop3    },
    [PFWL_PROTOCOL_IMAP]     = {"IMAP"    , check_imap    },
    [PFWL_PROTOCOL_SSL]      = {"SSL"     , check_ssl     },
    [PFWL_PROTOCOL_HANGOUT]  = {"Hangout" , check_hangout },
    [PFWL_PROTOCOL_WHATSAPP] = {"WhatsApp", check_whatsapp},
    [PFWL_PROTOCOL_TELEGRAM] = {"Telegram", check_telegram},
    [PFWL_PROTOCOL_DROPBOX]  = {"Dropbox" , check_dropbox },
    [PFWL_PROTOCOL_SPOTIFY]  = {"Spotify" , check_spotify },
};

void pfwl_parse_L7(pfwl_state_t* state, pfwl_dissection_info_t *dissection_info) {
  pfwl_flow_info_t* flow_info = NULL;
  pfwl_flow_t* flow = NULL;

  flow = pfwl_flow_table_find_or_create_flow(state->flow_table, dissection_info,
                                             state->protocols_to_inspect, state->tcp_reordering_enabled);

  if (unlikely(flow == NULL)) {
    dissection_info->status = PFWL_ERROR_MAX_FLOWS;
    return;
  }

  flow_info = &(flow->info);

  if(flow_info->last_rebuilt_ip_fragments){
    free((void*) flow_info->last_rebuilt_ip_fragments);
    flow_info->last_rebuilt_ip_fragments = NULL;
  }

  if(dissection_info->status == PFWL_STATUS_IP_LAST_FRAGMENT){
    flow_info->last_rebuilt_ip_fragments = dissection_info->pkt_refragmented;
  }

  dissection_info->status = PFWL_STATUS_OK;
  pfwl_parse_L7_stateless(state, dissection_info, flow_info);

  if (dissection_info->status == PFWL_STATUS_TCP_CONNECTION_TERMINATED) {
    pfwl_flow_table_delete_flow_later(state->flow_table, flow);
  }
}

void pfwl_parse_L7_stateless(pfwl_state_t* state, pfwl_dissection_info_t *identification_info, pfwl_flow_info_t* flow) {
  identification_info->status = PFWL_STATUS_OK;
  identification_info->user_flow_data = &(flow->tracking.udata);
  pfwl_protocol_l7_t i;

  uint8_t check_result = PFWL_PROTOCOL_NO_MATCHES;
  const pfwl_protocol_l7_t* well_known_ports;
  const unsigned char* app_data = identification_info->pkt_refragmented + identification_info->offset_l7;
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
    if (flow->l7prot < PFWL_NUM_PROTOCOLS && state->fields_to_extract_num[flow->l7prot]) {
      pfwl_protocol_descriptor_t descr = protocols_descriptors[flow->l7prot];
      (*(descr.dissector))(app_data, data_length, identification_info, t, state->inspectors_accuracy[flow->l7prot], state->fields_to_extract);
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
        check_result = (*(descr.dissector))(app_data, data_length, identification_info, t, state->inspectors_accuracy[i], state->fields_to_extract);
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

pfwl_protocol_l7_t pfwl_guess_protocol(pfwl_dissection_info_t identification_info) {
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
