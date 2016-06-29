/**
 * rtp.c
 *
 * Created on: 29/06/2016
 *
 * =========================================================================
 *  Copyright (C) 2012-2013, Daniele De Sensi (d.desensi.software@gmail.com)
 *  Copyright (C) 2016, Lorenzo Mangani (lorenzo.mangani@gmail.com), QXIP BV
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
#include <string.h>
#include <stdio.h>


#define DPI_DEBUG_RTP 0
#define debug_print(fmt, ...) \
            do { if (DPI_DEBUG_RTP) fprintf(stdout, fmt, __VA_ARGS__); } while (0)


u_int8_t check_rtp(dpi_library_state_t* state, dpi_pkt_infos_t* pkt, const unsigned char* app_data, u_int32_t data_length, dpi_tracking_informations_t* t){



	if ( data_length < 2 || pkt->dstport <= 1024 || pkt->srcport <= 1024 ) {
	    return DPI_PROTOCOL_NO_MATCHES;
	}


  	//struct ndpi_packet_struct *packet = &flow->packet;
  	u_int8_t payloadType, data_type = app_data[1] & 0x7F;
  	u_int32_t *ssid = (u_int32_t*)&app_data[8];

	if(data_length >= 12) {
		if ( (app_data[0] & 0xFF) == 0x80 || (app_data[0] & 0xFF) == 0xA0 ) /* RTP magic byte[1] */
		{
  		 	  return DPI_PROTOCOL_MATCHES;
		}
	}

	return DPI_PROTOCOL_NO_MATCHES;
}

