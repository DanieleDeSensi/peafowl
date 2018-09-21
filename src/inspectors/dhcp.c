/*
 * dhcp.c
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
#define PFWL_DHCP_MAGIC_COOKIE 0x63538263
#define PFWL_DHCP_TYPE 0x0135
#elif __BYTE_ORDER == __BIG_ENDIAN
#define PFWL_DHCP_MAGIC_COOKIE 0x63825363
#define PFWL_DHCP_TYPE 0x3501
#else
#error "Please fix <bits/endian.h>"
#endif

uint8_t check_dhcp(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                   const unsigned char* app_data, uint32_t data_length,
                   pfwl_tracking_informations_t* t) {
  if (pkt->l4prot != IPPROTO_UDP) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }
  if (data_length >= 244 && /** Minimum data_length. **/
      /** Ports check. **/
      ((pkt->srcport == port_dhcp_1 && pkt->dstport == port_dhcp_2) ||
       (pkt->dstport == port_dhcp_1 && pkt->srcport == port_dhcp_2)) &&
      /** Magic cookie. **/
      get_u32(app_data, 236) == PFWL_DHCP_MAGIC_COOKIE &&
      /**
       * First two bytes of DHCP message type.
       * Are the same for any DHCP message type.
       **/
      get_u16(app_data, 240) == PFWL_DHCP_TYPE) {
    return PFWL_PROTOCOL_MATCHES;
  } else {
    return PFWL_PROTOCOL_NO_MATCHES;
  }
}
