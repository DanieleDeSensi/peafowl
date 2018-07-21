/**
 * sip.c
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

int sipmatch(const char *body)
{
	// TODO: Non c'è controllo sulla lunghezza del pacchetto, potrebbe accedere a memoria non allocata (fuori pacchetto)
	const char *c;
	c = body;
	for (; *c; c++) {
	        if( ( (*c == ' ') && ( *(c+1) == 'S' ) && ( *(c+3) == 'P' ) && (*(c+5) == '2') && (*(c+6) == '.') ))
                               {
                                      return 1;
                               }
        }
	return 0;

}

#define DPI_DEBUG_SIP 0
#define debug_print(fmt, ...) \
            do { if (DPI_DEBUG_SIP) fprintf(stdout, fmt, __VA_ARGS__); } while (0)

#define DPI_SIP_NUM_REQUESTS 1
#define DPI_SIP_MAX_REQUEST_LENGTH 1
static const char* const requests[DPI_SIP_NUM_REQUESTS]={
   	   " SIP/2.0"
};

#define DPI_SIP_MSG_CHECK 0
#define DPI_SIP_NUM_MESSAGES_TO_MATCH 2
#define DPI_SIP_NUM_REQUESTS_MATCH 11
static const char* const requests_match[DPI_SIP_NUM_REQUESTS_MATCH]={
	    "INVITE "
	   ,"REGISTER "
	   ,"BYE "
	   ,"CANCEL "
	   ,"OPTIONS "
	   ,"NOTIFY "
	   ,"100 Try"
	   ,"180 Rin"
	   ,"200 OK"
	   ,"ACK "
	   ,"PUBLISH "
};



u_int8_t check_sip(dpi_library_state_t* state, dpi_pkt_infos_t* pkt, const unsigned char* app_data, u_int32_t data_length, dpi_tracking_informations_t* t){
	u_int8_t i;

	 if(pkt->dstport==port_sip || pkt->srcport==port_sip){
		return DPI_PROTOCOL_MATCHES;
	 }

	for(i=0; i<DPI_SIP_NUM_REQUESTS; i++){
		if(sipmatch((const char*) app_data)){
				return DPI_PROTOCOL_MATCHES;
		}
	}

	if (DPI_SIP_MSG_CHECK){
 	  for(i=0; i<DPI_SIP_NUM_REQUESTS_MATCH; i++){
		if(strncasecmp((const char*) app_data, requests_match[i], (sizeof(requests_match[i])/sizeof(*requests_match[i]) - 1) )==0){
			if(++t->num_sip_matched_messages==DPI_SIP_NUM_MESSAGES_TO_MATCH){
				return DPI_PROTOCOL_MATCHES;
			}else
				return DPI_PROTOCOL_MORE_DATA_NEEDED;
		}
	  }
	}

	return DPI_PROTOCOL_NO_MATCHES;
}

