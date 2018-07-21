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

static u_int8_t isValidMSRTPType(u_int8_t payloadType) {
  switch(payloadType) {
  case 0: /* G.711 u-Law */
  case 3: /* GSM 6.10 */
  case 4: /* G.723.1  */
  case 8: /* G.711 A-Law */
  case 9: /* G.722 */
  case 13: /* Comfort Noise */
  case 18: /* G.729 */
  case 34: /* H.263 [MS-H26XPF] */
  case 96: /* Dynamic RTP */
  case 97: /* Redundant Audio Data Payload */
  case 101: /* DTMF */
  case 103: /* SILK Narrowband */
  case 104: /* SILK Wideband */
  case 111: /* Siren */
  case 112: /* G.722.1 */
  case 114: /* RT Audio Wideband */
  case 115: /* RT Audio Narrowband */
  case 116: /* G.726 */
  case 117: /* G.722 */
  case 118: /* Comfort Noise Wideband */
  case 121: /* RT Video */
  case 122: /* H.264 [MS-H264PF] */
  case 123: /* H.264 FEC [MS-H264PF] */
  case 127: /* x-data */
    return(1 /* RTP */);
    break;
    
  case 200: /* RTCP PACKET SENDER */
  case 201: /* RTCP PACKET RECEIVER */
  case 202: /* RTCP Source Description */
  case 203: /* RTCP Bye */
    return(2 /* RTCP */);
    break;
    
  default:
    return(0);
  }
}


u_int8_t check_rtp(dpi_library_state_t* state, dpi_pkt_infos_t* pkt, const unsigned char* app_data, u_int32_t data_length, dpi_tracking_informations_t* t){

	if ( data_length < 2 || pkt->dstport <= 1024 || pkt->srcport <= 1024 ) {
	    return DPI_PROTOCOL_NO_MATCHES;
	}

  	u_int8_t payloadType, data_type = app_data[1] & 0x7F;
    // TODO: Accede ad app_data[8] senza controllare che la lunghezza di app_data (data_length) sia almeno 8
  	u_int32_t *ssid = (u_int32_t*)&app_data[8];

	if(data_length >= 12) {
		if ( (app_data[0] & 0xFF) == 0x80 || (app_data[0] & 0xFF) == 0xA0 ) /* RTP magic byte[1] */
		{

			if ( ((data_type < 72) || (data_type > 76)) && ((data_type <= 34)
	 		     || ((data_type >= 96) && (data_type <= 127) ) ) && (*ssid != 0) )
			{
  		 	  return DPI_PROTOCOL_MATCHES;
			}

			else if ( (payloadType = isValidMSRTPType(app_data[1] & 0xFF)) && (payloadType == 1 ) )
			{
  		 	  return DPI_PROTOCOL_MATCHES;
			}
		} else {
			  return DPI_PROTOCOL_MORE_DATA_NEEDED;
		}
	}

	return DPI_PROTOCOL_NO_MATCHES;
}

