/*
 * protocols_identifiers.h
 *
 *  Created on: 03/apr/2013
 *
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

#ifndef PROTOCOLS_IDENTIFIERS_H_
#define PROTOCOLS_IDENTIFIERS_H_

#include <netinet/ip.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define DPI_IP_VERSION_4 0x4
#define DPI_IP_VERSION_6 0x6

/** ATTENTION: These two values must be greater than DPI_NUM_PROTOCOLS. **/
#define DPI_PROTOCOL_NOT_DETERMINED 254
#define DPI_PROTOCOL_UNKNOWN 255

/** Old protocols identifiers (DEPRECATED). Use 'protocols' enum below. **/
enum old_protocols_udp {
  DPI_PROTOCOL_UDP_DNS = 0,
  DPI_PROTOCOL_UDP_MDNS,
  DPI_PROTOCOL_UDP_DHCP,
  DPI_PROTOCOL_UDP_DHCPv6,
  DPI_PROTOCOL_UDP_NTP,
  DPI_PROTOCOL_UDP_SIP,
  DPI_PROTOCOL_UDP_RTP,
  DPI_PROTOCOL_UDP_SKYPE,
  DPI_NUM_UDP_PROTOCOLS,
};

enum old_protocols_tcp {
  DPI_PROTOCOL_TCP_HTTP,
  DPI_PROTOCOL_TCP_BGP,
  DPI_PROTOCOL_TCP_SMTP,
  DPI_PROTOCOL_TCP_POP3,
  DPI_PROTOCOL_TCP_SSL,
  DPI_NUM_TCP_PROTOCOLS
};

enum protocols {
  DPI_PROTOCOL_DNS = 0,
  DPI_PROTOCOL_MDNS,
  DPI_PROTOCOL_DHCP,
  DPI_PROTOCOL_DHCPv6,
  DPI_PROTOCOL_NTP,
  DPI_PROTOCOL_SIP,
  DPI_PROTOCOL_RTP,
  DPI_PROTOCOL_SKYPE,
  DPI_PROTOCOL_HTTP,
  DPI_PROTOCOL_BGP,
  DPI_PROTOCOL_SMTP,
  DPI_PROTOCOL_POP3,
  DPI_PROTOCOL_SSL,
  DPI_NUM_PROTOCOLS
};

/** Remember to set the callback in init() and to increase the number of
 * supported protocols. **/

typedef uint8_t dpi_l7_prot_id;
typedef struct dpi_protocol {
  uint8_t l4prot; /** Id corresponds to the id defined for IPv4 protocol field
                     (IPv6 next header field). **/
  dpi_l7_prot_id l7prot;
} dpi_protocol_t;

static inline dpi_l7_prot_id dpi_old_protocols_to_new(dpi_protocol_t p) {
  if (p.l4prot == IPPROTO_UDP) {
    switch (p.l7prot) {
      case DPI_PROTOCOL_UDP_DNS:
        return DPI_PROTOCOL_DNS;
      case DPI_PROTOCOL_UDP_MDNS:
        return DPI_PROTOCOL_MDNS;
      case DPI_PROTOCOL_UDP_DHCP:
        return DPI_PROTOCOL_DHCP;
      case DPI_PROTOCOL_UDP_DHCPv6:
        return DPI_PROTOCOL_DHCPv6;
      case DPI_PROTOCOL_UDP_NTP:
        return DPI_PROTOCOL_NTP;
      case DPI_PROTOCOL_UDP_SIP:
        return DPI_PROTOCOL_SIP;
      case DPI_PROTOCOL_UDP_RTP:
        return DPI_PROTOCOL_RTP;
      case DPI_PROTOCOL_UDP_SKYPE:
        return DPI_PROTOCOL_SKYPE;
    }
  } else if (p.l4prot == IPPROTO_TCP) {
    switch (p.l7prot) {
      case DPI_PROTOCOL_TCP_HTTP:
        return DPI_PROTOCOL_HTTP;
      case DPI_PROTOCOL_TCP_BGP:
        return DPI_PROTOCOL_BGP;
      case DPI_PROTOCOL_TCP_SMTP:
        return DPI_PROTOCOL_SMTP;
      case DPI_PROTOCOL_TCP_POP3:
        return DPI_PROTOCOL_POP3;
      case DPI_PROTOCOL_TCP_SSL:
        return DPI_PROTOCOL_SSL;
    }
  }
  return DPI_NUM_PROTOCOLS;
}

static inline dpi_l7_prot_id dpi_new_protocols_to_old(dpi_l7_prot_id p) {
  switch (p) {
    case DPI_PROTOCOL_DNS:
      return DPI_PROTOCOL_UDP_DNS;
    case DPI_PROTOCOL_MDNS:
      return DPI_PROTOCOL_UDP_MDNS;
    case DPI_PROTOCOL_DHCP:
      return DPI_PROTOCOL_UDP_DHCP;
    case DPI_PROTOCOL_DHCPv6:
      return DPI_PROTOCOL_UDP_DHCPv6;
    case DPI_PROTOCOL_NTP:
      return DPI_PROTOCOL_UDP_NTP;
    case DPI_PROTOCOL_SIP:
      return DPI_PROTOCOL_UDP_SIP;
    case DPI_PROTOCOL_RTP:
      return DPI_PROTOCOL_UDP_RTP;
    case DPI_PROTOCOL_SKYPE:
      return DPI_PROTOCOL_UDP_SKYPE;
    case DPI_PROTOCOL_HTTP:
      return DPI_PROTOCOL_TCP_HTTP;
    case DPI_PROTOCOL_BGP:
      return DPI_PROTOCOL_TCP_BGP;
    case DPI_PROTOCOL_SMTP:
      return DPI_PROTOCOL_TCP_SMTP;
    case DPI_PROTOCOL_POP3:
      return DPI_PROTOCOL_TCP_POP3;
    case DPI_PROTOCOL_SSL:
      return DPI_PROTOCOL_TCP_SSL;
  }
  return DPI_PROTOCOL_UNKNOWN;
}

/**
 *  Inspectors must catch all the possible packet types during the message
 *exchange.
 *  E.g. inspect which detect only request or response are not valid inspectors.
 *	They must be able to detect flow that already started.
 *
 *	MUST never happen that two protocols match over the same packet. Is
 *preferable to have an inspector that 'take time' and
 *	returns DPI_PROTOCOL_MORE_DATA_NEEDED (to check more packets) up to the
 *point in which it is not sure that the protocol matches.
 */

enum protocol_check_statuses {
  DPI_PROTOCOL_MATCHES = 0, /** If the protocol matches for sure. */
  DPI_PROTOCOL_NO_MATCHES,  /** If the protocol doesn't matches for sure. */
  DPI_PROTOCOL_MORE_DATA_NEEDED, /** The inspector needs more data to be sure
                                    that the protocol matches or to invoke the
                                    callback on the complete data. **/
  DPI_PROTOCOL_ERROR
};

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define port_smtp_1 0x1900   /** 25 **/
#define port_dns 0x3500      /** 53 **/
#define port_dhcp_1 0x4300   /** 67 **/
#define port_dhcp_2 0x4400   /** 68 **/
#define port_http 0x5000     /** 80 **/
#define port_pop3 0x6E00     /** 110 **/
#define port_ntp 0x7B00      /** 123 **/
#define port_bgp 0xB300      /** 179 **/
#define port_dhcpv6_1 0x2202 /** 546 **/
#define port_dhcpv6_2 0x2302 /** 547 **/
#define port_smtp_2 0x4B02   /** 587 **/
#define port_sip 0x13C4      /** 5060 **/
#define port_mdns 0xE914     /** 5353 **/
#define port_ssl 0xBB01      /** 443 **/
#elif __BYTE_ORDER == __BIG_ENDIAN
#define port_smtp_1 0x0019   /** 25 **/
#define port_dns 0x0035      /** 53 **/
#define port_dhcp_1 0x0043   /** 67 **/
#define port_dhcp_2 0x0044   /** 68 **/
#define port_http 0x0050     /** 80 **/
#define port_pop3 0x006E     /** 110 **/
#define port_ntp 0x007B      /** 123 **/
#define port_bgp 0x00B3      /** 179 **/
#define port_dhcpv6_1 0x0222 /** 546 **/
#define port_dhcpv6_2 0x0223 /** 547 **/
#define port_smtp_2 0x024B   /** 587 **/
#define port_sip 0xC413      /** 5060 **/
#define port_mdns 0x14E9     /** 5353 **/
#define port_ssl 0x01BB      /** 443 **/
#else
#error "Please fix <bits/endian.h>"
#endif

#endif /* PROTOCOLS_IDENTIFIERS_H_ */
