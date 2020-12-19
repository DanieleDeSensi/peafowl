/*
 * quic5.c
 *
 * Protocol specification: https://tools.ietf.org/html/draft-tsvwg-quic-protocol-00
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
#include "quic_ssl_utils.h"
#include "quic_tls13.h"
#include "quic_utils.h"

#define MAX_CONNECTION_ID_LENGTH 	20
#define MAX_VERSION_LENGTH	 	4
#define MAX_STRING_LENGTH	 	256
#define MAX_SALT_LENGTH			20
#define MAX_LABEL_LENGTH		32
#define HASH_SHA2_256_LENGTH		32
#define TLS13_AEAD_NONCE_LENGTH		12

typedef struct {
	unsigned int first_byte;
	size_t dst_conn_id_len;
	unsigned char dst_conn_id[MAX_CONNECTION_ID_LENGTH];
	size_t src_conn_id_len;
	unsigned char src_conn_id[MAX_CONNECTION_ID_LENGTH];
	size_t header_len;
	unsigned char version[MAX_VERSION_LENGTH];
	size_t packet_number;
	size_t packet_number_len;
	size_t payload_len;
	
	unsigned char *decrypted_payload;
	size_t decrypted_payload_len;

	const EVP_CIPHER *quic_cipher_mode;

	unsigned char quic_secret[HASH_SHA2_256_LENGTH];
	size_t quic_secret_len;

	unsigned char quic_key[32];
	size_t quic_key_len;
	unsigned char quic_hp[32];
	size_t quic_hp_len;
	unsigned char quic_iv[TLS13_AEAD_NONCE_LENGTH];
	size_t quic_iv_len;
	unsigned int has_tls13_record;
} quic_t;

/* Quic Versions */
typedef enum {
	VER_Q024=0x51303234,
	VER_Q025=0x51303235,
	VER_Q030=0x51303330,
	VER_Q033=0x51303333,
	VER_Q034=0x51303334,
	VER_Q035=0x51303335,
	VER_Q037=0x51303337,
	VER_Q039=0x51303339,
	VER_Q043=0x51303433,
	VER_Q046=0x51303436,
	VER_Q050=0x51303530,
	VER_T050=0x54303530,
	VER_T051=0x54303531,
	VER_MVFST_22=0xfaceb001,
	VER_MVFST_27=0xfaceb002,
	VER_MVFST_EXP=0xfaceb00e,
} quic_version_t;

#define PFWL_DEBUG_DISS_QUIC 1
#define debug_print(fmt, ...)                                                  \
  do {                                                                         \
    if (PFWL_DEBUG_DISS_QUIC)                                               \
      fprintf(stdout, fmt, __VA_ARGS__);                                       \
  } while (0)

static size_t convert_length_connection(size_t len){
  switch(len){
    case 0x0C:
      return 8;
    case 0x08:
      return 4;
    case 0x04:
      return 1;
    case 0x00:
      return 0;
    default:
      return 0;
  }
}

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

/**
 * Compute the client and server initial secrets given Connection ID "cid".
 */
static int quic_derive_initial_secrets(quic_t *quic_info) {
	/*
	 * https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.2
	 *
	 * initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
	 *
	 * client_initial_secret = HKDF-Expand-Label(initial_secret,
	 *                                           "client in", "", Hash.length)
	 *
	 * Hash for handshake packets is SHA-256 (output size 32).
	 */
	static const uint8_t ver_q050_salt[MAX_SALT_LENGTH] = { 0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE, 0x2F, 0x9D, 0x94, 0x5C, 0xFC, 0xDB, 0xD3, 0xA7, 0xF0, 0xD3, 0xB5, 0x6B, 0x45 };
	static const uint8_t ver_t050_salt[MAX_SALT_LENGTH] = { 0x7f, 0xf5, 0x79, 0xe5, 0xac, 0xd0, 0x72, 0x91, 0x55, 0x80, 0x30, 0x4c, 0x43, 0xa2, 0x36, 0x7c, 0x60, 0x48, 0x83, 0x10 };
	static const uint8_t ver_t051_salt[MAX_SALT_LENGTH] = { 0x7a, 0x4e, 0xde, 0xf4, 0xe7, 0xcc, 0xee, 0x5f, 0xa4, 0x50, 0x6c, 0x19, 0x12, 0x4f, 0xc8, 0xcc, 0xda, 0x6e, 0x03, 0x3d };
	const uint8_t	*salt; 
	uint32_t v	= ntohl(*(uint32_t *)(&quic_info->version[0]));

	switch (v) {
		case VER_Q050:
			salt = ver_q050_salt;
			quic_info->has_tls13_record = 0;
			break;

		case VER_T050:
			salt = ver_t050_salt;
			quic_info->has_tls13_record = 1;
			break;

		case VER_T051:
			salt = ver_t051_salt;
			quic_info->has_tls13_record = 1;
			break;
		default:
			printf("Error matching the quic version to a salt using standard salt instead\n");
			salt = ver_q050_salt;
			quic_info->has_tls13_record = 0;
	}

	uint8_t secret[HASH_SHA2_256_LENGTH];
	const size_t s_len = HASH_SHA2_256_LENGTH;
	int len = HKDF_Extract(salt, (sizeof(uint8_t) * MAX_SALT_LENGTH), quic_info->dst_conn_id, quic_info->dst_conn_id_len, secret, s_len);	
	if(0 > len) {
		printf("Failed to extract secrets\n");
		return -1;
	}

	unsigned char   label[MAX_LABEL_LENGTH] = { 0 };
	size_t          label_len = 0;
	/* TODO MAKE 32 configurable or at least explain why it is 32 */
        label_len = hkdf_create_tls13_label(32, "client in", label, sizeof(label));
        quic_info->quic_secret_len = HKDF_Expand(secret, len, label, label_len, quic_info->quic_secret, s_len);
	return 0;
}

/*
 * (Re)initialize the PNE/PP ciphers using the given cipher algorithm.
 * If the optional base secret is given, then its length MUST match the hash
 * algorithm output.
 */
static int quic_cipher_prepare(quic_t *quic_info)
{
	//TODO MAKE CIPHER LEN DYNAMIC
	uint32_t 	cipher_keylen 	= 16; /* 128 bit cipher length == 16 bytes storage */
        unsigned char   label_key[MAX_LABEL_LENGTH] 	= { 0 };
        size_t          label_key_len 	= 0;
	unsigned char   label_iv[MAX_LABEL_LENGTH] 	= { 0 };
        size_t          label_iv_len 	= 0;
	unsigned char   label_hp[MAX_LABEL_LENGTH] 	= { 0 };
        size_t          label_hp_len 	= 0;

	label_key_len 	= hkdf_create_tls13_label(cipher_keylen, "quic key", label_key, sizeof(label_key));
        label_iv_len 	= hkdf_create_tls13_label(TLS13_AEAD_NONCE_LENGTH, "quic iv", label_iv, sizeof(label_iv));
        label_hp_len 	= hkdf_create_tls13_label(cipher_keylen, "quic hp", label_hp, sizeof(label_hp));

	quic_info->quic_key_len = HKDF_Expand(quic_info->quic_secret, quic_info->quic_secret_len, label_key, label_key_len, quic_info->quic_key, cipher_keylen);
	quic_info->quic_iv_len	= HKDF_Expand(quic_info->quic_secret, quic_info->quic_secret_len, label_iv, label_iv_len, quic_info->quic_iv, TLS13_AEAD_NONCE_LENGTH);
	quic_info->quic_hp_len	= HKDF_Expand(quic_info->quic_secret, quic_info->quic_secret_len, label_hp, label_hp_len, quic_info->quic_hp, cipher_keylen);
	return 0;
}

/**
 * Given a QUIC message (header + non-empty payload), the actual packet number,
 * try to decrypt it using the cipher.
 * As the header points to the original buffer with an encrypted packet number,
 * the (encrypted) packet number length is also included.
 *
 * The actual packet number must be constructed according to
 * https://tools.ietf.org/html/draft-ietf-quic-transport-22#section-12.3
 */
static int quic_decrypt_message(quic_t *quic_info, const uint8_t *packet_payload, uint32_t packet_payload_len)
{
	uint8_t *header;
	uint8_t nonce[TLS13_AEAD_NONCE_LENGTH];
	uint8_t atag[16];

	/* Copy header, but replace encrypted first byte and PKN by plaintext. */
	header = (uint8_t *)memdup(packet_payload, quic_info->header_len);
	if(!header)
		return -1;
	header[0] = quic_info->first_byte;
	for(uint32_t i = 0; i < quic_info->packet_number_len; i++) {
		header[quic_info->header_len - 1 - i] = (uint8_t)(quic_info->packet_number >> (8 * i));
	}

	/* Input is "header || ciphertext (buffer) || auth tag (16 bytes)" */
	quic_info->decrypted_payload_len = packet_payload_len - (quic_info->header_len + 16);
	if(quic_info->decrypted_payload_len == 0) {
		printf("Decryption not possible, ciphertext is too short\n");
		free(header);
		return -1;
	}
	quic_info->decrypted_payload = (unsigned char *)memdup(packet_payload + quic_info->header_len, quic_info->decrypted_payload_len);
	if(!quic_info->decrypted_payload) {
		free(header);
		return -1;
	}
	memcpy(atag, packet_payload + quic_info->header_len + quic_info->decrypted_payload_len, 16);
	memcpy(nonce, quic_info->quic_iv, TLS13_AEAD_NONCE_LENGTH);
	/* Packet number is left-padded with zeroes and XORed with write_iv */
	phton64(nonce + sizeof(nonce) - 8, pntoh64(nonce + sizeof(nonce) - 8) ^ quic_info->packet_number);

        /* Initial packets are protected with AEAD_AES_128_GCM. */
        quic_info->decrypted_payload_len = aes_gcm_decrypt(quic_info->decrypted_payload, quic_info->decrypted_payload_len,
		EVP_aes_128_gcm(), header, quic_info->header_len, atag, quic_info->quic_key, nonce, sizeof(nonce), quic_info->decrypted_payload);
	free(header);
	return 0;
}

static int remove_header_protection(quic_t *quic_info, const unsigned char *app_data) {
	unsigned char 	ciphertext[128] = { 0 };
	// https://tools.ietf.org/html/draft-ietf-quic-tls-22#section-5.4.1 
	unsigned char 	first_byte  	= app_data[0];
	unsigned char 	mask[5] 	= { 0 };


	/* Sample is always 16 bytes and starts after PKN (assuming length 4).
		https://tools.ietf.org/html/draft-ietf-quic-tls-22#section-5.4.2 */
	size_t 		sample_pos 	=  quic_info->header_len + 4;
	size_t 		sample_len 	= 16;
	unsigned char 	*sample 	= (unsigned char *)app_data + sample_pos;

	/* Encrypt in-place with AES-ECB and extract the mask. */
        /* Packet numbers are protected with AES128-CTR */
	int res = aes_encrypt(sample, sample_len, EVP_aes_128_ecb(), quic_info->quic_hp, NULL, ciphertext);
	if (0 > res) {
		printf("Error encrypting sample\n");
		return -1;
	}

	memcpy(mask, ciphertext, sizeof(mask));
	if((first_byte & 0x80) == 0x80) {
		/* Long header: 4 bits masked */
		first_byte ^= mask[0] & 0x0f;
	} else {
		/* Short header: 5 bits masked */
		first_byte ^= mask[0] & 0x1f;
	}
	quic_info->packet_number_len = (first_byte & 0x03) + 1;

	quic_info->packet_number = 0;
	for(size_t i = 0; i < quic_info->packet_number_len; i++) {
		quic_info->packet_number |= (size_t)(app_data[quic_info->header_len + i] ^ mask[1 + i]) << (8 * (quic_info->packet_number_len - 1 - i));
	}
	/* Increase header length with packet number length */
	quic_info->header_len += quic_info->packet_number_len;
	quic_info->first_byte = first_byte;
	return 0;
}

int decrypt_first_packet(quic_t *quic_info, const unsigned char *app_data, size_t data_length) {
	
	if(0 > quic_derive_initial_secrets(quic_info)) {
		printf("Error quic_derive_initial_secrets\n");
		return -1;
	}

	if(0 > quic_cipher_prepare(quic_info)) {
		printf("Error quic_cipher_prepare\n");
		return -1;
	}

	if (0 > remove_header_protection(quic_info, app_data)) {
		printf("Error removing error protection\n");
		return -1;
	}

	if (0 > quic_decrypt_message(quic_info, app_data, data_length)) {
		printf("Error decrypting message\n");
		return -1;
	}
	return 0;
}

uint8_t check_quic5(pfwl_state_t *state, const unsigned char *app_data,
		size_t data_length, pfwl_dissection_info_t *pkt_info,
		pfwl_flow_info_private_t *flow_info_private){

	quic_t 	quic_info;
	char	*scratchpad = state->scratchpad + state->scratchpad_next_byte;

	memset(&quic_info, 0, sizeof(quic_t));
	if(data_length >= 1200){
		//size_t connection_id_len = convert_length_connection(app_data[0] & 0x0C);
		//size_t unused_bits = app_data[0] & 0xC0;
		//int has_version = app_data[0] & 0x01;

		size_t header_form = (app_data[0] & 0x80) >> 7; // 1000 0000
		//size_t bit2 = (app_data[0] & 0x40) >> 6; // 0100 0000
		//size_t bit3 = (app_data[0] & 0x20) >> 5; // 0010 0000
		//size_t bit4 = (app_data[0] & 0x10) >> 4; // 0001 0000
		//size_t bit5 = (app_data[0] & 0x08) >> 3; // 0000 1000
		//size_t bit6 = (app_data[0] & 0x04) >> 2; // 0000 0100
		//size_t bit7 = (app_data[0] & 0x02) >> 1; // 0000 0010
		//size_t bit8 = (app_data[0] & 0x01);      // 0000 0001	

		if(header_form) { /* Long packet type */
			//size_t version_offset 		= 0;
			//version_offset = 1; // 1 byte
			quic_info.header_len++; // First byte header

			memcpy(quic_info.version, &app_data[1], 4);

			//uint32_t *t = (uint32_t *)&app_data[1];
			quic_info.header_len += 4; /* version (4 bytes) */

			quic_info.dst_conn_id_len = app_data[quic_info.header_len];
			quic_info.header_len++; //1 byte destionation connection length 

			memcpy(quic_info.dst_conn_id, &app_data[quic_info.header_len], quic_info.dst_conn_id_len);
			quic_info.header_len = quic_info.header_len + quic_info.dst_conn_id_len; /* destination connection id length */

			quic_info.src_conn_id_len = app_data[quic_info.header_len];
			quic_info.header_len++; //1 byte source connection length 

			memcpy(quic_info.src_conn_id, &app_data[quic_info.header_len], quic_info.src_conn_id_len);
			quic_info.header_len = quic_info.header_len + quic_info.src_conn_id_len; /* source connection id length */ 	

			size_t token_len = 0;
			quic_info.header_len += quic_get_variable_len(app_data, quic_info.header_len, &token_len);
			quic_info.header_len += token_len;

			quic_info.header_len += quic_get_variable_len(app_data, quic_info.header_len, &quic_info.payload_len);

			if (0 > decrypt_first_packet(&quic_info, app_data, data_length)) {
				return PFWL_PROTOCOL_NO_MATCHES;
			}

		} else { /* Short packet type */
			return PFWL_PROTOCOL_NO_MATCHES;
		}

		if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_QUIC_VERSION)) {
			scratchpad = state->scratchpad + state->scratchpad_next_byte;
			memcpy(scratchpad, quic_info.version, 4);
			pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_VERSION, scratchpad, 4);
			state->scratchpad_next_byte += 4;
		}


		if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_QUIC_SNI) || 
				pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_QUIC_UAID)) {
			//unsigned int 	frame_type 		= quic_info.decrypted_payload[0];
			//unsigned int 	offset 			= quic_info.decrypted_payload[1];
	
			size_t  crypto_data_size = 0;	
			size_t	crypto_data_len	= quic_get_variable_len(quic_info.decrypted_payload, 2, &crypto_data_size);
			/* According to wireshark chlo_start could also be quic_info.decrypted_payload + 2 (frame_type || offset) + crypto_data_len */

			if (quic_info.has_tls13_record) {
				check_tls13(state, quic_info.decrypted_payload, quic_info.decrypted_payload_len, pkt_info, flow_info_private);
			} else {
				/* PLZ Move me to a function */
				const unsigned char* chlo_start = (const unsigned char*) pfwl_strnstr((const char*) quic_info.decrypted_payload, "CHLO", quic_info.decrypted_payload_len);
				if(chlo_start){
					printf("debug chlo found\n");
					size_t num_tags = (chlo_start[4] & 0xFF) + ((chlo_start[5] & 0xFF) << 8);
					size_t start_tags = ((const unsigned char*) chlo_start - quic_info.decrypted_payload)  + 8;
					size_t start_content = start_tags + num_tags*8;
					u_int32_t last_offset_end = 0;
					for(size_t i = start_tags; i < crypto_data_size; i += 8){
						u_int32_t offset_end 	= 0;
						u_int32_t length	= 0;
						u_int32_t offset	= 0;
						if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_QUIC_SNI)) {
							if(quic_info.decrypted_payload[i]     == 'S' &&
									quic_info.decrypted_payload[i + 1] == 'N' &&
									quic_info.decrypted_payload[i + 2] == 'I' &&
									quic_info.decrypted_payload[i + 3] == 0){ 
								offset_end = quic_getu32(quic_info.decrypted_payload, i + 4);
								length = offset_end - last_offset_end;
								offset = last_offset_end;
								if(start_content + offset + length  <= data_length){
									scratchpad = state->scratchpad + state->scratchpad_next_byte;
									memcpy(scratchpad, &quic_info.decrypted_payload[start_content + offset], length);
									pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_SNI, scratchpad, length);
									state->scratchpad_next_byte += length;
								} 
							}	
						}
						if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_QUIC_UAID)) { 
							if (quic_info.decrypted_payload[i] == 'U' &&
									quic_info.decrypted_payload[i+1] == 'A' &&
									quic_info.decrypted_payload[i+2] == 'I' &&
									quic_info.decrypted_payload[i+3] == 'D') {
								offset_end = quic_getu32(quic_info.decrypted_payload, i + 4);
								length = offset_end - last_offset_end;
								offset = last_offset_end;
								if(start_content + offset + length  <= data_length){
									scratchpad = state->scratchpad + state->scratchpad_next_byte; 
									memcpy(scratchpad, &quic_info.decrypted_payload[start_content + offset], length);
									pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_UAID, scratchpad, length);
									state->scratchpad_next_byte += length;
								}

							}
						}
						last_offset_end = quic_getu32(quic_info.decrypted_payload, i + 4);
					}
				}
			}
		}
		free(quic_info.decrypted_payload);
		return PFWL_PROTOCOL_MATCHES;
	}
	return PFWL_PROTOCOL_NO_MATCHES;
}
#else
uint8_t check_quic5(pfwl_state_t *state, const unsigned char *app_data,
		size_t data_length, pfwl_dissection_info_t *pkt_info,
		pfwl_flow_info_private_t *flow_info_private){
	return PFWL_PROTOCOL_NO_MATCHES;
}
#endif
