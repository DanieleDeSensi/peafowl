/*
 * quic_tls13.c
 *
 * TLS 1.3 record layer decoder for newer quic versions
 *
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 * Copyright (c) 2020 SoftAtHome (david.cluytens@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * =========================================================================
 */

#include <peafowl/inspectors/inspectors.h>
#include <peafowl/peafowl.h>

#ifdef HAVE_OPENSSL

#include <openssl/bio.h>
#include <openssl/evp.h>
#include "quic_tls13.h"
#include "quic_utils.h"
#include "quic_ssl_utils.h"

/*
 *	 GREASE_TABLE Ref: 
 * 		- https://tools.ietf.org/html/draft-davidben-tls-grease-00
 * 		- https://tools.ietf.org/html/draft-davidben-tls-grease-01
 *
 * 	switch grease-table is much faster than looping and testing a lookup grease table 
 *
 */
static unsigned int is_grease(uint32_t x){
	switch(x) {
		case 0x0a0a:
		case 0x1a1a:
		case 0x2a2a:
		case 0x3a3a:
		case 0x4a4a:
		case 0x5a5a:
		case 0x6a6a:
		case 0x7a7a:
		case 0x8a8a:
		case 0x9a9a:
		case 0xaaaa:
		case 0xbaba:
		case 0xcaca:
		case 0xdada:
		case 0xeaea:
		case 0xfafa:
			return 1;
		default:
			return 0;
	}
	return 0;
}

void tls13_parse_google_user_agent(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private) {
        char *scratchpad = state->scratchpad + state->scratchpad_next_byte;
        memcpy(scratchpad, data, len);
        pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_UAID, scratchpad, len);
        state->scratchpad_next_byte += len;
}

void tls13_parse_quic_transport_params(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private) {
	size_t		pointer = 0;
	size_t 		TLVlen 	= 0;
	for (pointer = 0; pointer <len; pointer += TLVlen) {
		size_t		TLVtype = 0;
		pointer += quic_get_variable_len(data, pointer, &TLVtype);
		TLVlen = data[pointer];
		pointer++;
		//printf("parameter TLV %08X TLV Size %02d\n", TLVtype, TLVlen);
		switch(TLVtype) {
			case 0x3129:
				if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_QUIC_UAID)) {
					tls13_parse_google_user_agent(state, data + pointer, TLVlen, pkt_info, flow_info_private);
				}
			default:
				break;
		}

	}
}

void tls13_parse_servername(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private) {
	size_t		pointer = 0;
	//uint16_t 	list_len = ntohs(*(uint16_t *)(data));
	//size_t 		type 	= data[2];
	uint16_t 	server_len = ntohs(*(uint16_t *)(data + 3));
	pointer	= 2 + 1 + 2;

	char *scratchpad = state->scratchpad + state->scratchpad_next_byte;
	memcpy(scratchpad, data + pointer, server_len);
	pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_SNI, scratchpad, server_len);
	state->scratchpad_next_byte += server_len;
}

void tls13_parse_extensions(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, 
	unsigned char *ja3_string, size_t *ja3_string_len) {
	size_t pointer;
	size_t TLVlen;

	for (pointer = 0; pointer < len; pointer += TLVlen) {
		size_t TLVtype = ntohs(*(uint16_t *)(&data[pointer]));
		pointer += 2;
		TLVlen = ntohs(*(uint16_t *)(&data[pointer]));
		pointer += 2;
		//printf("TLV %02d TLV Size %02d\n", TLVtype, TLVlen);

		switch(TLVtype) {
			/* skip grease values */
			case 0x0a0a:
			case 0x1a1a:
			case 0x2a2a:
			case 0x3a3a:
                        case 0x4a4a:
			case 0x5a5a:
			case 0x6a6a:
			case 0x7a7a:
                        case 0x8a8a:
			case 0x9a9a:
			case 0xaaaa:
			case 0xbaba:
                        case 0xcaca:
			case 0xdada:
			case 0xeaea:
			case 0xfafa:
				/* Grease values must be ignored */
				continue;
				break;

			/* Server Name */
			case 0:
				if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_QUIC_SNI)) {
					tls13_parse_servername(state, data + pointer, TLVlen, pkt_info, flow_info_private);
				}
				break;
				/* Extension quic transport parameters */
			case 65445:
				tls13_parse_quic_transport_params(state, data + pointer, TLVlen, pkt_info, flow_info_private);
				break;
			default:
				break;
		}	
		*ja3_string_len += sprintf(ja3_string + *ja3_string_len, "%u-", TLVtype);

	}
	if (len) {
		*ja3_string_len = *ja3_string_len - 1; //remove last dash (-) from ja3_string
	}
}

uint8_t check_tls13(pfwl_state_t *state, const unsigned char *tls_data, size_t tls_data_length, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private) {
	/* Finger printing */
	unsigned char ja3_string[1024];
	size_t ja3_string_len;

	size_t 		tls_pointer	= 0;

	/* Parse TLS record header */
	//size_t tls_record_frame_type = tls_data[tls_pointer];
	tls_pointer++;

	//size_t tls_record_offset     = tls_data[tls_pointer];
	tls_pointer++;

	//uint16_t tls_record_len	     = ntohs(*(uint16_t *)(&tls_data[tls_pointer]));
	tls_pointer += 2;

	/* Parse TLS Handshake protocol */
	size_t	handshake_type = tls_data[tls_pointer];
	tls_pointer++;

	//size_t 	length = (tls_data[tls_pointer] << 16) + (tls_data[tls_pointer+1] << 8) + tls_data[tls_pointer+2];
	tls_pointer += 3;

	uint16_t tls_version = ntohs(*(uint16_t *)(&tls_data[tls_pointer]));
	tls_pointer += 2;

	/* Build JA3 string */
	ja3_string_len = sprintf(ja3_string, "%d,", tls_version);

	if (handshake_type == 1) { /* We only inspect client hello which has a type equal to 1 */	
		/* skipping random data 32 bytes */
		tls_pointer += 32;

		/* skipping legacy_session_id one byte */
		tls_pointer += 1;

		/* Cipher suites and length */
		uint16_t cipher_suite_len = ntohs(*(uint16_t *)(&tls_data[tls_pointer]));
		tls_pointer += 2;

		/* use content of cipher suite for building the JA3 hash */
		for (size_t i = 0; i < cipher_suite_len; i += 2) {
			uint16_t cipher_suite = ntohs(*(uint16_t *)(tls_data + tls_pointer + i));
			if(is_grease(cipher_suite)) {
				continue; // skip grease value
			}
			ja3_string_len += sprintf(ja3_string + ja3_string_len, "%d-", cipher_suite);
		}
		if (cipher_suite_len) {
			ja3_string_len--; //remove last dash (-) from ja3_string
		}
		ja3_string_len += sprintf(ja3_string + ja3_string_len, ",");
		tls_pointer += cipher_suite_len;

		/* compression methods length */
		size_t compression_methods_len = tls_data[tls_pointer];
		tls_pointer++;

		/* Skip compression methods */
		tls_pointer += compression_methods_len;

		/* Extension length */
		uint16_t ext_len = ntohs(*(uint16_t *)(&tls_data[tls_pointer]));
		tls_pointer += 2;

		/* Add Extension length to the ja3 string */
		unsigned const char *ext_data = tls_data + tls_pointer;

		/* lets iterate over the exention list */
		tls13_parse_extensions(state, ext_data, ext_len, pkt_info, flow_info_private, ja3_string, &ja3_string_len);
		ja3_string_len += sprintf(ja3_string + ja3_string_len, ",,");
	}
	//printf("JA3 String %s\n", ja3_string);
        char *md5sum = state->scratchpad + state->scratchpad_next_byte;
	size_t md5sum_len = md5_digest_message(ja3_string, ja3_string_len, md5sum);
        
	pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_JA3, md5sum, md5sum_len);
        state->scratchpad_next_byte += md5sum_len;

	//printf("JA3:");
	//debug_print_rawfield(md5sum, 0, md5sum_len);
	return PFWL_PROTOCOL_MATCHES;
}

#else
uint8_t check_tls13(pfwl_state_t *state, const unsigned char *app_data,
		size_t data_length, pfwl_dissection_info_t *pkt_info,
		pfwl_flow_info_private_t *flow_info_private){
	return PFWL_PROTOCOL_NO_MATCHES;
}
#endif
