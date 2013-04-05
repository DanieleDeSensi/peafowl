/**
 * smtp.c
 *
 * Created on: 22/11/2012
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
#include <string.h>
#include <stdio.h>


#define DPI_DEBUG_SMTP 0
#define debug_print(fmt, ...) \
            do { if (DPI_DEBUG_SMTP) fprintf(stdout, fmt, __VA_ARGS__); } while (0)

#define DPI_SMTP_NUM_MESSAGES_TO_MATCH 3

#define DPI_SMTP_NUM_RESPONSES 22

#define DPI_SMTP_MAX_RESPONSE_LENGTH 3
static const char* const responses[DPI_SMTP_NUM_RESPONSES]={
		 "500"
		,"501"
		,"502"
		,"503"
		,"504"
		,"550"
		,"551"
		,"552"
		,"553"
		,"554"
		,"211"
		,"214"
		,"220"
		,"221"
		,"250"
		,"251"
		,"252"
		,"354"
		,"421"
		,"450"
		,"451"
		,"452"
};

#define DPI_SMTP_NUM_REQUESTS 11
#define DPI_SMTP_MAX_REQUEST_LENGTH 5
static const char* const requests[DPI_SMTP_NUM_REQUESTS]={
		"EHLO "
	   ,"EXPN "
	   ,"HELO "
	   ,"HELP "
	   ,"MAIL "
	   ,"DATA "
	   ,"RCPT "
	   ,"RSET "
	   ,"NOOP "
	   ,"QUIT "
	   ,"VRFY "
};


u_int8_t check_smtp(dpi_library_state_t* state, dpi_pkt_infos_t* pkt, const unsigned char* app_data, u_int32_t data_length, dpi_tracking_informations_t* t){
	u_int8_t i;
	if(data_length<DPI_SMTP_MAX_RESPONSE_LENGTH){
		return DPI_PROTOCOL_MORE_DATA_NEEDED;
	}

	if(data_length>=DPI_SMTP_MAX_RESPONSE_LENGTH){
		for(i=0; i<DPI_SMTP_NUM_RESPONSES; i++){
			if(strncasecmp((const char*) app_data, responses[i], DPI_SMTP_MAX_RESPONSE_LENGTH)==0){
				if(++t->num_smtp_matched_messages==DPI_SMTP_NUM_MESSAGES_TO_MATCH){
					return DPI_PROTOCOL_MATCHES;
				}else
					return DPI_PROTOCOL_MORE_DATA_NEEDED;
			}
		}
	}

	if(data_length>=DPI_SMTP_MAX_REQUEST_LENGTH){
		for(i=0; i<DPI_SMTP_NUM_REQUESTS; i++){
			if(strncasecmp((const char*) app_data, requests[i], DPI_SMTP_MAX_REQUEST_LENGTH)==0){
				if(++t->num_smtp_matched_messages==DPI_SMTP_NUM_MESSAGES_TO_MATCH){
					return DPI_PROTOCOL_MATCHES;
				}else
					return DPI_PROTOCOL_MORE_DATA_NEEDED;
			}
		}
	}

	return DPI_PROTOCOL_NO_MATCHES;
}

