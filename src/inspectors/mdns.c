/*
 * mdns.c
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

#include <peafowl/peafowl.h>
#include <peafowl/inspectors/inspectors.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define PFWL_MDNS_IPv4_DEST_ADDRESS 0xFB0000E0
#elif __BYTE_ORDER == __BIG_ENDIAN
#define PFWL_MDNS_IPv4_DEST_ADDRESS 0xE00000FB
#else
#error "Please fix <bits/endian.h>"
#endif

const struct in6_addr PFWL_MDNS_IPV6_DEST_ADDRESS = {
    .s6_addr = {0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0xFB}};

uint8_t check_mdns(pfwl_state_t* state, pfwl_pkt_infos_t* pkt,
                   const unsigned char* app_data, uint32_t data_length,
                   pfwl_tracking_informations_t* t) {
  if (pkt->l4prot != IPPROTO_UDP) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }
  if (pkt->dstport == port_mdns && data_length >= 12) {
    if (pkt->ip_version == PFWL_IP_VERSION_4 &&
        pkt->dst_addr_t.ipv4_dstaddr == PFWL_MDNS_IPv4_DEST_ADDRESS) {
      return PFWL_PROTOCOL_MATCHES;
    } else if (pkt->ip_version == PFWL_IP_VERSION_6 &&
               pfwl_v6_addresses_equal(pkt->dst_addr_t.ipv6_dstaddr,
                                      PFWL_MDNS_IPV6_DEST_ADDRESS)) {
      return PFWL_PROTOCOL_MATCHES;
    }
  }
  return PFWL_PROTOCOL_NO_MATCHES;
}
