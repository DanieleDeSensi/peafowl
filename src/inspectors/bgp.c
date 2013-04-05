/*
 * bgp.c
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

u_int8_t check_bgp(dpi_library_state_t* state, dpi_pkt_infos_t* pkt, const unsigned char* app_data, u_int32_t data_length, dpi_tracking_informations_t* t){
	if(data_length>18){
	   if(get_u64(app_data, 0) == 0xffffffffffffffffULL &&
	   get_u64(app_data, 8) == 0xffffffffffffffffULL &&
	   ntohs(get_u16(app_data, 16)) <= data_length &&
	   (pkt->dstport==port_bgp || pkt->srcport==port_bgp)
	   && app_data[18] < 5){
		   return DPI_PROTOCOL_MATCHES;
	   }else
		   return DPI_PROTOCOL_NO_MATCHES;
	}else
		return DPI_PROTOCOL_MORE_DATA_NEEDED;
}

