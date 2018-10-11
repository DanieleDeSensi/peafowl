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

static const pfwl_protocol_l7_t
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

static const pfwl_protocol_l7_t
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

static const pfwl_protocol_descriptor_t  protocols_descriptors[PFWL_NUM_PROTOCOLS] =
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

void pfwl_parse_L7(pfwl_state_t* state, const unsigned char* pkt, size_t length,
                   uint32_t timestamp, pfwl_dissection_info_t *dissection_info,
                   pfwl_flow_info_private_t* flow_info_private) {
  // In this case, this function has been directly called by the user.
  if(!dissection_info->l3.refrag_pkt){
    dissection_info->l3.refrag_pkt = pkt;
    dissection_info->l3.refrag_pkt_len = length;
    dissection_info->l3.length = 0;
    dissection_info->l4.length = 0;
  }
  dissection_info->l7.length = length;

  pfwl_protocol_l7_t i;
  uint8_t check_result = PFWL_PROTOCOL_NO_MATCHES;
  const pfwl_protocol_l7_t* well_known_ports;

  if (flow_info_private->l7prot < PFWL_NUM_PROTOCOLS) {
    if (state->fields_to_extract_num[flow_info_private->l7prot]) {
      pfwl_protocol_descriptor_t descr = protocols_descriptors[flow_info_private->l7prot];
      (*(descr.dissector))(state, pkt, length, dissection_info, flow_info_private);
    }
    return;
  } else if (flow_info_private->l7prot == PFWL_PROTOCOL_NOT_DETERMINED) {
    if (dissection_info->l4.protocol == IPPROTO_TCP && state->active_protocols > 0) {
      well_known_ports = pfwl_well_known_ports_association_tcp;
    } else if (dissection_info->l4.protocol == IPPROTO_UDP && state->active_protocols > 0) {
      well_known_ports = pfwl_well_known_ports_association_udp;
    } else {
      return;
    }

    pfwl_protocol_l7_t first_protocol_to_check;
    pfwl_protocol_l7_t checked_protocols = 0;

    if ((first_protocol_to_check = well_known_ports[dissection_info->l4.port_src]) ==
            PFWL_PROTOCOL_UNKNOWN &&
        (first_protocol_to_check = well_known_ports[dissection_info->l4.port_dst]) ==
            PFWL_PROTOCOL_UNKNOWN) {
      first_protocol_to_check = 0;
    }

    for (i = first_protocol_to_check; checked_protocols < PFWL_NUM_PROTOCOLS;
         i = (i + 1) % PFWL_NUM_PROTOCOLS, ++checked_protocols) {
      if (BITTEST(flow_info_private->possible_matching_protocols, i)) {
        pfwl_protocol_descriptor_t descr = protocols_descriptors[i];
        check_result = (*(descr.dissector))(state, pkt, length, dissection_info, flow_info_private);
        if (check_result == PFWL_PROTOCOL_MATCHES) {
          flow_info_private->l7prot = i;
          dissection_info->l7.protocol = flow_info_private->l7prot;
          return;
        } else if (check_result == PFWL_PROTOCOL_NO_MATCHES) {
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
      flow_info_private->l7prot = PFWL_PROTOCOL_UNKNOWN;
    }
  }

  dissection_info->l7.protocol = flow_info_private->l7prot;

  return;
}

pfwl_protocol_l7_t pfwl_guess_protocol(pfwl_dissection_info_t identification_info) {
  pfwl_protocol_l7_t r = PFWL_PROTOCOL_UNKNOWN;
  if (identification_info.l4.protocol == IPPROTO_TCP) {
    r = pfwl_well_known_ports_association_tcp[identification_info.l4.port_src];
    if (r == PFWL_PROTOCOL_UNKNOWN)
      r = pfwl_well_known_ports_association_tcp[identification_info.l4.port_dst];
  } else if (identification_info.l4.protocol == IPPROTO_UDP) {
    r = pfwl_well_known_ports_association_udp[identification_info.l4.port_src];
    if (r == PFWL_PROTOCOL_UNKNOWN)
      r = pfwl_well_known_ports_association_udp[identification_info.l4.port_dst];
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
