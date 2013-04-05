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


#include "inspectors.h"

#if __BYTE_ORDER == __LITTLE_ENDIAN
	#define DPI_MDNS_IPv4_DEST_ADDRESS 0xFB0000E0
#elif __BYTE_ORDER == __BIG_ENDIAN
	#define DPI_MDNS_IPv4_DEST_ADDRESS 0xE00000FB
#else
# error	"Please fix <bits/endian.h>"
#endif

const struct in6_addr DPI_MDNS_IPV6_DEST_ADDRESS={.s6_addr={0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFB}};

u_int8_t check_mdns(dpi_library_state_t* state, dpi_pkt_infos_t* pkt, const unsigned char* app_data, u_int32_t data_length, dpi_tracking_informations_t* t){
	if(pkt->dstport==port_mdns && data_length>=12){
		if(pkt->ip_version==DPI_IP_VERSION_4 && pkt->dst_addr_t.ipv4_dstaddr==DPI_MDNS_IPv4_DEST_ADDRESS){
			return DPI_PROTOCOL_MATCHES;
		}else if(pkt->ip_version==DPI_IP_VERSION_6 && dpi_v6_addresses_equal(pkt->dst_addr_t.ipv6_dstaddr, DPI_MDNS_IPV6_DEST_ADDRESS)){
			return DPI_PROTOCOL_MATCHES;
		}
	}
	return DPI_PROTOCOL_NO_MATCHES;
}

