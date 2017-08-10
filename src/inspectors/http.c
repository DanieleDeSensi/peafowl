/*
 * http.c
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
#include "http_parser_joyent.h"
#include "../api.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define DPI_DEBUG_HTTP 0

#define debug_print(fmt, ...) \
            do { if (DPI_DEBUG_HTTP) fprintf(stdout, fmt, __VA_ARGS__); } while (0)

/**
 * Activate HTTP callbacks. When a protocol is identified the default behavior is to not inspect the packets belonging to that
 * flow anymore and keep simply returning the same protocol identifier.
 *
 * If a callback is enabled for a certain protocol, then we keep inspecting all the new flows with that protocol in order to invoke
 * the callbacks specified by the user on the various parts of the message. Moreover, if the application protocol uses TCP,
 * then we have the additional cost of TCP reordering for all the segments.
 * Is highly recommended to enable TCP reordering if it is not already enabled (remember that is enabled by default).
 * Otherwise the informations extracted could be erroneous/incomplete.
 *
 * The pointers to the data passed to the callbacks are valid only for the duration of the callback.
 *
 * @param state       A pointer to the state of the library.
 * @param callbacks   A pointer to HTTP callbacks.
 * @param user_data   A pointer to global user HTTP data. This pointer will be passed to any HTTP callback when it is invoked.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded, DPI_STATE_UPDATE_FAILURE otherwise.
 *
 **/
u_int8_t dpi_http_activate_callbacks(dpi_library_state_t* state, dpi_http_callbacks_t* callbacks, void* user_data){
	if(state && callbacks->num_header_types<=128){
		BITSET(state->tcp_protocols_to_inspect, DPI_PROTOCOL_TCP_HTTP);
		BITSET(state->tcp_active_callbacks, DPI_PROTOCOL_TCP_HTTP);
		state->http_callbacks_user_data=user_data;
		state->http_callbacks=callbacks;
		return DPI_STATE_UPDATE_SUCCESS;
	}else{
		return DPI_STATE_UPDATE_FAILURE;
	}
}

/**
 * Disable the HTTP callbacks. user_data is not freed/modified.
 * @param state       A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded, DPI_STATE_UPDATE_FAILURE otherwise.
 */
u_int8_t dpi_http_disable_callbacks(dpi_library_state_t* state){
	if(state){
		BITCLEAR(state->tcp_active_callbacks, DPI_PROTOCOL_TCP_HTTP);
		state->http_callbacks=NULL;
		state->http_callbacks_user_data=NULL;
		return DPI_STATE_UPDATE_SUCCESS;
	}else{
		return DPI_STATE_UPDATE_FAILURE;
	}
}

/**
 * Manages the case in which an HTTP request/response is divided in more segments.
 * @return 1 if the HTTP field of interest is complete, 0 if more segments are needed, 2 if an error occurred.
 */
#ifndef DPI_DEBUG
static
#endif
u_int8_t dpi_http_manage_pdu_reassembly(http_parser* parser, const char *at, size_t length, char** temp_buffer, size_t* size){
	/**
	 * If I have old data present, I have anyway to concatenate the new data.
	 * Then, if copy==0, I can free the data after the use, otherwise I simply
	 * return and I wait for other data.
	 */
	if(*temp_buffer){
		char* tmp=realloc(*temp_buffer, *size+length);
		if(!tmp){
			free(*temp_buffer);
			return 2;
		}
		*temp_buffer=tmp;
		memcpy(*temp_buffer+*size, at, length);
		*size+=length;
	}


	if(parser->copy){
		if(*temp_buffer==NULL){
			*temp_buffer=malloc(length*sizeof(char));

			if(!*temp_buffer) return 2;
			memcpy(*temp_buffer, at, length);
			*size=length;
		}
		return 0;
	}
	return 1;
}



#ifndef DPI_DEBUG
static
#endif
int on_url(http_parser* parser, const char *at, size_t length){
	dpi_http_internal_informations_t* infos=(dpi_http_internal_informations_t*) parser->data;
	dpi_http_callbacks_t* callbacks=infos->callbacks;

	const char *real_data=at;
	size_t real_length=length;
	u_int8_t segmentation_result=dpi_http_manage_pdu_reassembly(parser, at, length, &(infos->temp_buffer), &(infos->temp_buffer_size));
	if(segmentation_result==0){
		return 0;
	}else if(segmentation_result==2){
		return 1;
	}else if(infos->temp_buffer){
		real_data=infos->temp_buffer;
		real_length=infos->temp_buffer_size;
	}

	(*callbacks->header_url_callback)((unsigned char*) real_data, real_length, infos->pkt_informations, infos->flow_specific_user_data, infos->user_data);

	free(infos->temp_buffer);
	infos->temp_buffer=NULL;
	infos->temp_buffer_size=0;

	return 0;
}

#ifndef DPI_DEBUG
static
#endif
int on_field(http_parser* parser, const char *at, size_t length){
	dpi_http_internal_informations_t* infos=(dpi_http_internal_informations_t*) parser->data;

	uint i;
	parser->parse_header_field=0;

	const char *real_data=at;
	size_t real_length=length;
	u_int8_t segmentation_result=dpi_http_manage_pdu_reassembly(parser, at, length, &(infos->temp_buffer), &(infos->temp_buffer_size));
	if(segmentation_result==0){
		return 0;
	}else if(segmentation_result==2){
		return 1;
	}else if(infos->temp_buffer){
		real_data=infos->temp_buffer;
		real_length=infos->temp_buffer_size;
	}

	for(i=0; i<infos->callbacks->num_header_types; i++){
		if(strncasecmp(real_data, infos->callbacks->header_names[i], real_length)==0){
			parser->header_type=i;
			parser->parse_header_field=1;
			break;
		}
	}

	free(infos->temp_buffer);
	infos->temp_buffer=NULL;
	infos->temp_buffer_size=0;

	return 0;
}

#ifndef DPI_DEBUG
static
#endif
int on_value(http_parser* parser, const char *at, size_t length){
	if(parser->parse_header_field){
		dpi_http_internal_informations_t* infos=(dpi_http_internal_informations_t*) parser->data;
		dpi_http_callbacks_t* callbacks=infos->callbacks;

		const char *real_data=at;
		size_t real_length=length;
		u_int8_t segmentation_result=dpi_http_manage_pdu_reassembly(parser, at, length, &(infos->temp_buffer), &(infos->temp_buffer_size));
		if(segmentation_result==0){
			return 0;
		}else if(segmentation_result==2){
			return 1;
		}else if(infos->temp_buffer){
			real_data=infos->temp_buffer;
			real_length=infos->temp_buffer_size;
		}

		dpi_http_message_informations_t dpi_http_informations;
		dpi_http_informations.http_version_major=parser->http_major;
		dpi_http_informations.http_version_minor=parser->http_minor;
		dpi_http_informations.request_or_response=parser->type;
		if(parser->type==HTTP_REQUEST)
			dpi_http_informations.method_or_code=parser->method;
		else
			dpi_http_informations.method_or_code=parser->status_code;
		(*callbacks->header_types_callbacks[parser->header_type])(&dpi_http_informations, (unsigned char*) real_data, real_length, infos->pkt_informations, infos->flow_specific_user_data, infos->user_data);

		free(infos->temp_buffer);
		infos->temp_buffer=NULL;
		infos->temp_buffer_size=0;
	}
	return 0;
}

#ifndef DPI_DEBUG
static
#endif
int on_header_complete(http_parser* parser){
	dpi_http_internal_informations_t* infos=(dpi_http_internal_informations_t*) parser->data;
	dpi_http_message_informations_t dpi_http_informations;
	dpi_http_informations.http_version_major=parser->http_major;
	dpi_http_informations.http_version_minor=parser->http_minor;
	dpi_http_informations.request_or_response=parser->type;
	if(parser->type==HTTP_REQUEST)
		dpi_http_informations.method_or_code=parser->method;
	else
		dpi_http_informations.method_or_code=parser->status_code;

	(*(infos->callbacks->header_completion_callback))(&dpi_http_informations, infos->pkt_informations, infos->flow_specific_user_data, infos->user_data);
	return 0;
}

#ifndef DPI_DEBUG
static
#endif
int on_body(http_parser* parser, const char *at, size_t length){
	dpi_http_internal_informations_t* infos=(dpi_http_internal_informations_t*) parser->data;
	dpi_http_callbacks_t* callbacks=infos->callbacks;

	dpi_http_message_informations_t dpi_http_informations;
	dpi_http_informations.http_version_major=parser->http_major;
	dpi_http_informations.http_version_minor=parser->http_minor;
	dpi_http_informations.request_or_response=parser->type;
	if(parser->type==HTTP_REQUEST)
		dpi_http_informations.method_or_code=parser->method;
	else
		dpi_http_informations.method_or_code=parser->status_code;

	(*callbacks->http_body_callback)(&dpi_http_informations, (unsigned char*) at, length, infos->pkt_informations, infos->flow_specific_user_data, infos->user_data, !parser->copy);

	free(infos->temp_buffer);
	infos->temp_buffer=NULL;
	infos->temp_buffer_size=0;
	return 0;
}


u_int8_t invoke_callbacks_http(dpi_library_state_t* state, dpi_pkt_infos_t* pkt, const unsigned char* app_data, u_int32_t data_length, dpi_tracking_informations_t* tracking){
	debug_print("%s\n", "[http.c] HTTP callback manager invoked.");
	u_int8_t ret=check_http(state, pkt, app_data, data_length, tracking);
	if(ret==DPI_PROTOCOL_NO_MATCHES){
		debug_print("%s\n", "[http.c] An error occurred in the HTTP protocol manager.");
		return DPI_PROTOCOL_ERROR;
	}else{
		debug_print("%s\n", "[http.c] HTTP callback manager exits.");
		return DPI_PROTOCOL_MATCHES;
	}
}


/**
 * I decided to avoid the concept of subprotocol. This indeed can easily be derived from host address so the user can include this identification
 * in its callback.
 */
u_int8_t check_http(dpi_library_state_t* state, dpi_pkt_infos_t* pkt, const unsigned char* app_data, u_int32_t data_length, dpi_tracking_informations_t* tracking){
	debug_print("%s\n","-------------------------------------------");
	debug_print("%s\n", "[http.c] Executing HTTP inspector...");

	http_parser* parser=&(tracking->http[pkt->direction]);

	/**
	 * We assume that dpi_tracking_informations_t is initialized to zero, so if data is NULL
	 * we know that it has not been initialized and we initialize it.
	 */
	if(parser->data==NULL){
		http_parser_init(parser, HTTP_BOTH);
		bzero(&(tracking->http_informations[pkt->direction]), sizeof(dpi_http_internal_informations_t));

		tracking->http_informations[pkt->direction].callbacks=((dpi_http_callbacks_t*) state->http_callbacks);
		tracking->http_informations[pkt->direction].user_data=state->http_callbacks_user_data;
		tracking->http_informations[pkt->direction].flow_specific_user_data=&(tracking->flow_specific_user_data);

		parser->data=&(tracking->http_informations[pkt->direction]);
	}
	tracking->http_informations[pkt->direction].pkt_informations=pkt;

	http_parser_settings x = { 0 };

	if(state->http_callbacks){
		if(((dpi_http_callbacks_t*) state->http_callbacks)->header_url_callback!=NULL)
			x.on_url=on_url;
		else
			x.on_url=0;

		if(((dpi_http_callbacks_t*) state->http_callbacks)->http_body_callback!=NULL)
			x.on_body=on_body;
		else
			x.on_body=0;

		if(((dpi_http_callbacks_t*) state->http_callbacks)->num_header_types!=0){
			x.on_header_field=on_field;
			x.on_header_value=on_value;
		}else{
			x.on_header_field=0;
			x.on_header_value=0;
		}

		if(((dpi_http_callbacks_t*) state->http_callbacks)->header_completion_callback!=NULL)
			x.on_headers_complete=on_header_complete;
		else
			x.on_headers_complete=0;
		x.on_message_begin=0;
		x.on_message_complete=0;
	}else{
		/** If there are no user callbacks, we can avoid to do PDU reassembly. **/
		free(((dpi_http_internal_informations_t*) parser->data)->temp_buffer);
		x.on_body=0;
		x.on_header_field=0;
		x.on_header_value=0;
		x.on_headers_complete=0;
		x.on_message_begin=0;
		x.on_message_complete=0;
		x.on_url=0;
	}

	http_parser_execute(parser, &x, (const char*) app_data, data_length);

	if(parser->http_errno==HPE_OK){
		debug_print("%s\n", "[http.c] HTTP matches");
		return DPI_PROTOCOL_MATCHES;
	}else{
		debug_print("[http.c] HTTP doesn't matches. Error: %s\n", http_errno_description(parser->http_errno));
		/**
		 * If the library didn't see the connection from the beginning,
		 * the inspector is not aligned with the current state of the protocol
		 * so we wait for new data, instead of returning a NO_MATCHES matches simply
		 * because we didn't analyzed the connection from the beginning. For example,
		 * if we start looking the flow in the middle of a large file transfer,
		 * the inspector is not able to determine if the flow is HTTP or not.
		 * Therefore, in this case, we keep inspecting also the successive
		 * packets. Anyway, after the maximum number of trials specified by the user,
		 * if we still didn't found the protocol, the library will mark the flow
		 * as unknown.
		 */
		if(tracking->seen_syn==0){
			http_parser_init(parser, HTTP_BOTH);
			return DPI_PROTOCOL_MORE_DATA_NEEDED;
		}else{
			return DPI_PROTOCOL_NO_MATCHES;
		}
	}
}
