/*
 * dns.c
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

u_int8_t check_dns(dpi_library_state_t* state, dpi_pkt_infos_t* pkt, const unsigned char* app_data, u_int32_t data_length, dpi_tracking_informations_t* t){
	/* Check standard DNS port (53) */
	if((pkt->dstport==port_dns || pkt->srcport==port_dns) && data_length>=12){
		if((app_data[2] & 0x80)==0){
			/** If QR==0 is a query. **/
			if(get_u16(app_data, 4)!=0 && /** QDCOUNT: For queries this field must be >= 1. **/
			   get_u16(app_data, 6)==0 && /** ANCOUNT **/
			   get_u16(app_data, 8)==0 /** NSCOUNT **/){
				return DPI_PROTOCOL_MATCHES;
			}else
				return DPI_PROTOCOL_NO_MATCHES;
		}else{ /** DNS response. **/
			return DPI_PROTOCOL_MATCHES;
		}
	}
	return DPI_PROTOCOL_NO_MATCHES;
}
