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

#define PFWL_IP_VERSION_4 0x4
#define PFWL_IP_VERSION_6 0x6

enum protocols {
  PFWL_PROTOCOL_DNS = 0,
  PFWL_PROTOCOL_MDNS,
  PFWL_PROTOCOL_DHCP,
  PFWL_PROTOCOL_DHCPv6,
  PFWL_PROTOCOL_NTP,
  PFWL_PROTOCOL_SIP,
  PFWL_PROTOCOL_RTP,
  PFWL_PROTOCOL_SSH,
  PFWL_PROTOCOL_SKYPE,
  PFWL_PROTOCOL_HTTP,
  PFWL_PROTOCOL_BGP,
  PFWL_PROTOCOL_SMTP,
  PFWL_PROTOCOL_POP3,
  PFWL_PROTOCOL_IMAP,
  PFWL_PROTOCOL_SSL,
  PFWL_PROTOCOL_HANGOUT,
  PFWL_PROTOCOL_WHATSAPP,
  PFWL_PROTOCOL_TELEGRAM,
  PFWL_PROTOCOL_DROPBOX,
  PFWL_PROTOCOL_SPOTIFY,
  PFWL_NUM_PROTOCOLS,
  PFWL_PROTOCOL_NOT_DETERMINED,
  PFWL_PROTOCOL_UNKNOWN
};

typedef uint8_t pfwl_protocol_l7;
typedef uint8_t pfwl_protocol_l4;

/**
 *  Inspectors must catch all the possible packet types during the message
 *exchange.
 *  E.g. inspect which detect only request or response are not valid inspectors.
 *	They must be able to detect flow that already started.
 *
 *	MUST never happen that two protocols match over the same packet. Is
 *preferable to have an inspector that 'take time' and
 *	returns PFWL_PROTOCOL_MORE_DATA_NEEDED (to check more packets) up to the
 *point in which it is not sure that the protocol matches.
 */

enum protocol_check_statuses {
  PFWL_PROTOCOL_MATCHES = 0, /** If the protocol matches for sure. */
  PFWL_PROTOCOL_NO_MATCHES,  /** If the protocol doesn't matches for sure. */
  PFWL_PROTOCOL_MORE_DATA_NEEDED, /** The inspector needs more data to be sure
                                    that the protocol matches or to invoke the
                                    callback on the complete data. **/
  PFWL_PROTOCOL_ERROR
};

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define port_ssh 0x1600      /** 22 **/
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
#define port_smtp_ssl 0xD101   /** 465 **/
#define port_sip 0xC413      /** 5060 **/
#define port_mdns 0xE914     /** 5353 **/
#define port_ssl 0xBB01      /** 443 **/
#define port_pop3_ssl 0xE303     /** 995 **/
#define port_imap 0x8F00     /** 143 **/
#define port_imap_ssl 0xE103 /** 993 **/
#define port_hangout_19302 0x664B /** 19302 **/
#define port_hangout_19303 0x674B /** 19303 **/
#define port_hangout_19304 0x684B /** 19304 **/
#define port_hangout_19305 0x694B /** 19305 **/
#define port_hangout_19306 0x6A4B /** 19306 **/
#define port_hangout_19307 0x6B4B /** 19307 **/
#define port_hangout_19308 0x6C4B /** 19308 **/
#define port_hangout_19309 0x4B6D /** 19309 **/
#define port_dropbox 0x5C44 /** 17500 **/
#define port_spotify 0x15E1 /** 57621 **/
#elif __BYTE_ORDER == __BIG_ENDIAN
#define port_ssh 0x0016      /* 22 **/
#define port_smtp_1 0x0019   /** 25 **/
#define port_dns 0x0035      /** 53 **/
#define port_dhcp_1 0x0043   /** 67 **/
#define port_dhcp_2 0x0044   /** 68 **/
#define port_http 0x0050     /** 80 **/
#define port_pop3 0x006E     /** 110 **/
#define port_pop3_ssl 0x03E3     /** 995 **/
#define port_imap 0x008F     /** 143 **/
#define port_imap_ssl 0x03E1 /** 993 **/
#define port_ntp 0x007B      /** 123 **/
#define port_bgp 0x00B3      /** 179 **/
#define port_dhcpv6_1 0x0222 /** 546 **/
#define port_dhcpv6_2 0x0223 /** 547 **/
#define port_smtp_2 0x024B   /** 587 **/
#define port_smtp_ssl 0x01D1   /** 465 **/
#define port_sip 0x13C4      /** 5060 **/
#define port_mdns 0x14E9     /** 5353 **/
#define port_ssl 0x01BB      /** 443 **/
#define port_hangout_19302 0x4B66 /** 19302 **/
#define port_hangout_19303 0x4B67 /** 19303 **/
#define port_hangout_19304 0x4B68 /** 19304 **/
#define port_hangout_19305 0x4B69 /** 19305 **/
#define port_hangout_19306 0x4B6A /** 19306 **/
#define port_hangout_19307 0x4B6B /** 19307 **/
#define port_hangout_19308 0x4B6C /** 19308 **/
#define port_hangout_19309 0x4B6D /** 19309 **/
#define port_dropbox 0x445C /** 17500 **/
#define port_spotify 0xE115 /** 57621 **/
#else
#error "Please fix <bits/endian.h>"
#endif

#endif /* PROTOCOLS_IDENTIFIERS_H_ */
