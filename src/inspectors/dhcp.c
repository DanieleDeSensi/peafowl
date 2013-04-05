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

#include "inspectors.h"
#if __BYTE_ORDER == __LITTLE_ENDIAN
	#define DPI_DHCP_MAGIC_COOKIE 0x63538263
	#define DPI_DHCP_TYPE 0x0135
#elif __BYTE_ORDER == __BIG_ENDIAN
	#define DPI_DHCP_MAGIC_COOKIE 0x63825363
	#define DPI_DHCP_TYPE 0x3501
#else
# error	"Please fix <bits/endian.h>"
#endif

u_int8_t check_dhcp(dpi_library_state_t* state, dpi_pkt_infos_t* pkt,
		            const unsigned char* app_data, u_int32_t data_length,
		            dpi_tracking_informations_t* t){
	if(data_length >= 244 && /** Minimum data_length. **/
	   /** Ports check. **/
	   ((pkt->srcport==port_dhcp_1 && pkt->dstport==port_dhcp_2) ||
	   (pkt->dstport==port_dhcp_1 && pkt->srcport==port_dhcp_2)) &&
	   /** Magic cookie. **/
	   get_u32(app_data, 236)==DPI_DHCP_MAGIC_COOKIE &&
	   /**
	    * First two bytes of DHCP message type.
	    * Are the same for any DHCP message type.
	    **/
	   get_u16(app_data, 240)==DPI_DHCP_TYPE){
		return DPI_PROTOCOL_MATCHES;
	}else{
		return DPI_PROTOCOL_NO_MATCHES;
	}
}
