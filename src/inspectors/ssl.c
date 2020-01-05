/*
 * ssl.c
 *
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
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
#include <peafowl/external/md5.h>

#include <stdio.h>

#define SSL_BIDIRECTIONAL 0 // If set to 1, before confirming that the flow is SSL, we expect to see SSL header in both directions

#define PFWL_DEBUG_SSL 0
#define debug_print(fmt, ...)                                                  \
  do {                                                                         \
  if (PFWL_DEBUG_SSL)                                                        \
  fprintf(stdout, fmt, __VA_ARGS__);                                       \
  } while (0)


#define PFWL_MAX_SSL_REQUEST_SIZE 10000

// GREASE_TABLE Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
const uint32_t GREASE_TABLE[] = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
                                 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
                                 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
                                 0xcaca, 0xdada, 0xeaea, 0xfafa};

uint is_grease(uint32_t x){
  size_t size = sizeof(GREASE_TABLE) / sizeof(GREASE_TABLE[0]);
  for(size_t i = 0; i < size; i++){
    if(x == GREASE_TABLE[i]){
      return 1;
    }
  }
  return 0;
}

typedef enum{
   HELLO_REQUEST       = 0x00,
   CLIENT_HELLO        = 0x01,
   SERVER_HELLO        = 0x02,
   CERTIFICATE         = 0x0b,
   SERVER_KEY_EXCHANGE = 0x0c,
   CERTIFICATE_REQUEST = 0x0d,
   SERVER_DONE         = 0x0e,
   CERTIFICATE_VERIFY  = 0x0f,
   CLIENT_KEY_EXCHANGE = 0x10,
   FINISHED            = 0x14,
}handshake_msg_types;

/* Can't call libc functions from kernel space, define some stub instead */

#define pfwl_isalpha(ch) (((ch) >= 'a' && (ch) <= 'z') || ((ch) >= 'A' && (ch) <= 'Z'))
#define pfwl_isdigit(ch) ((ch) >= '0' && (ch) <= '9')
#define pfwl_isspace(ch) (((ch) >= '\t' && (ch) <= '\r') || ((ch) == ' '))
#define pfwl_isprint(ch) ((ch) >= 0x20 && (ch) <= 0x7e)
#define pfwl_ispunct(ch) (((ch) >= '!' && (ch) <= '/') ||	\
  ((ch) >= ':' && (ch) <= '@') ||	\
  ((ch) >= '[' && (ch) <= '`') ||	\
  ((ch) >= '{' && (ch) <= '~'))

static int check_punycode_string(char * buffer , int len)
{
  int i = 0;

  while(i++ < len)
  {
    if( buffer[i] == 'x' &&
        buffer[i+1] == 'n' &&
        buffer[i+2] == '-' &&
        buffer[i+3] == '-' )
      // is a punycode string
      return 1;
  }
  // not a punycode string
  return 0;
}

static void stripCertificateTrailer(char *buffer, int* buffer_len) {

  int i, is_puny;

  //  printf("->%s<-\n", buffer);

  for(i = 0; i < *buffer_len; i++) {
    // printf("%c [%d]\n", buffer[i], buffer[i]);

    if((buffer[i] != '.')
       && (buffer[i] != '-')
       && (buffer[i] != '_')
       && (buffer[i] != '*')
       && (!pfwl_isalpha(buffer[i]))
       && (!pfwl_isdigit(buffer[i]))) {
      buffer[i] = '\0';
      *buffer_len = i;
      break;
    }
  }

  /* check for punycode encoding */
  is_puny = check_punycode_string(buffer, *buffer_len);

  // not a punycode string - need more checks
  if(is_puny == 0) {

    if(i > 0) i--;

    while(i > 0) {
      if(!pfwl_isalpha(buffer[i])) {
        buffer[i] = '\0';
        *buffer_len = i;
        i--;
      } else
        break;
    }

    for(i = *buffer_len; i > 0; i--) {
      if(buffer[i] == '.') break;
      else if(pfwl_isdigit(buffer[i]))
        buffer[i] = '\0', *buffer_len = i;
    }
  }
}

static int processExtensions(pfwl_state_t* state, pfwl_flow_info_private_t* flow_info_private, int offset, const unsigned char* payload, uint16_t extensions_len, uint extension_offset, size_t data_length,
	                      char *buffer, int buffer_len, pfwl_field_t* fields, uint32_t* next_server_extension, uint32_t* remaining_extension_len, size_t scratchpad_start,
                        uint8_t handshake_msg_type){
  char* extensions = state->scratchpad + state->scratchpad_next_byte;
  size_t ja3_last_byte = 0;
  size_t extensions_next_char = 0;
  size_t ellcurves_offset = 0;
  size_t ellpoints_offset = 0;
  uint8_t ellcurves_present = 0;
  uint8_t ellpoints_present = 0;
  while(extension_offset < extensions_len) {
  	if(offset + extension_offset > data_length){
  		*next_server_extension = offset + extension_offset - data_length;
  		*remaining_extension_len = extensions_len - extension_offset;
  		return 2;
  	}
    u_int16_t extension_id, extension_len;

    extension_id = ntohs(*((u_int16_t*)&payload[offset+extension_offset]));
    extension_offset += 2;

    extension_len = ntohs(*((u_int16_t*)&payload[offset+extension_offset]));
    extension_offset += 2;

#if PFWL_DEBUG_SSL
    printf("SSL [extension_id: %u][extension_len: %u]\n", extension_id, extension_len);                    
#endif    

    if((pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_EXTENSIONS) || 
       pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3)) && 
       !is_grease(extension_id)){
      extensions_next_char += sprintf(extensions + extensions_next_char, "%d-", extension_id);
    }

    // TODO Check that offset + extension_offset + extension_len < data_length
    if(extension_id == 0) {
      u_int begin = 0,len;
      char *server_name = (char*)&payload[offset+extension_offset];

      while(begin < extension_len) {
        if((!pfwl_isprint(server_name[begin]))
           || pfwl_ispunct(server_name[begin])
           || pfwl_isspace(server_name[begin]))
          begin++;
        else
          break;
      }

      len = (u_int)PFWL_MIN(extension_len-begin, buffer_len-1);
      strncpy(buffer, &server_name[begin], len);
      buffer[len] = '\0';
      stripCertificateTrailer(buffer, (int*) &buffer_len);
#if PFWL_DEBUG_SSL
      printf("SNI: %s\n", buffer);
#endif
      // Do not set from buffer since is allocated on stack.
      pfwl_field_string_set(fields, PFWL_FIELDS_L7_SSL_SNI, (const unsigned char*) &server_name[begin], buffer_len);
    }else if(extension_id == 10 && extension_len > 2){
      // Elliptic curves
      ellcurves_present = 1;
      ellcurves_offset = extension_offset;
    }else if(extension_id == 11 && extension_len > 2){
      // EllipticCurvePointFormat
      ellpoints_present = 1;
      ellpoints_offset = extension_offset;
    }

    extension_offset += extension_len;
  }
  // Set extensions
  if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_EXTENSIONS) ||
     pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3)){
    // Remove last dash
    if(extensions_next_char){
      extensions_next_char -= 1; 
    }
    // Comma not needed for JA3S because extensions is the lasts field.
    if(handshake_msg_type == CLIENT_HELLO){
      sprintf(extensions + extensions_next_char, ",");
      state->scratchpad_next_byte += extensions_next_char + 1; // +1 for the comma
    }else{
      state->scratchpad_next_byte += extensions_next_char;
      ja3_last_byte = state->scratchpad_next_byte;
    }
#if PFWL_DEBUG_SSL
    printf("Extensions: %s\n", extensions);
    printf("SPAD: %s\n", state->scratchpad);
#endif    
    pfwl_field_string_set(fields, PFWL_FIELDS_L7_SSL_EXTENSIONS, (const unsigned char*) extensions, extensions_next_char);
  }
  // Set elliptic curves
  if((pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES) ||
      pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3))){
    if(ellcurves_present){
      u_int16_t ell_curves_len = ntohs(get_u16(payload, offset + ellcurves_offset));
      uint16_t next_curve = 0;
      char* curves = state->scratchpad + state->scratchpad_next_byte;
      size_t curves_next_char = 0;
      ellcurves_offset += 2; // Skip the length
      while(next_curve < ell_curves_len){
        uint16_t curve_id = ntohs(get_u16(payload, offset + ellcurves_offset + next_curve));
        if(!is_grease(curve_id)){
          curves_next_char += sprintf(curves + curves_next_char, "%d-", curve_id);
        }
        next_curve += 2;
      }
      // Remove last dash
      if(curves_next_char){
        curves_next_char -= 1; 
      }
      sprintf(curves + curves_next_char, ",");
      state->scratchpad_next_byte += curves_next_char + 1; // +1 for the comma
#if PFWL_DEBUG_SSL
      printf("Curves: %s\n", curves);
      printf("SPAD: %s\n", state->scratchpad);
#endif    
      pfwl_field_string_set(fields, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES, (const unsigned char*) curves, curves_next_char);
    }else if(handshake_msg_type == CLIENT_HELLO){
      sprintf(state->scratchpad + state->scratchpad_next_byte, ",");
      state->scratchpad_next_byte += 1;
    }
  }

  // Set elliptic curves point format
  if((pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES_POINT_FMTS) ||
      pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3))){
    if(ellpoints_present){
      uint8_t ell_points_len = get_u8(payload, offset + ellpoints_offset);
      uint16_t next_point = 0;
      char* points = state->scratchpad + state->scratchpad_next_byte;
      size_t points_next_char = 0;
      ellpoints_offset += 1; // Skip the length
      while(next_point < ell_points_len){
        uint8_t point_id = get_u8(payload, offset + ellpoints_offset + next_point);
        if(!is_grease(point_id)){
          points_next_char += sprintf(points + points_next_char, "%d-", point_id);
        }
        next_point += 1;
      }
      // Remove last dash
      if(points_next_char){
        points_next_char -= 1; 
      }
      state->scratchpad_next_byte += points_next_char;
#if PFWL_DEBUG_SSL
      printf("CurvesPointFmt: %s\n", points);
      printf("SPAD: %s\n", state->scratchpad);
#endif    
      pfwl_field_string_set(fields, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES_POINT_FMTS, (const unsigned char*) points, points_next_char);
    }
    if(handshake_msg_type == CLIENT_HELLO){
      ja3_last_byte = state->scratchpad_next_byte;
    }
  }

  // Compute JA3
  pfwl_string_t dummy, dummy2;
  if((pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3)) &&
     !pfwl_field_string_get(fields, PFWL_FIELDS_L7_SSL_VERSION_HANDSHAKE, &dummy)   &&
     !pfwl_field_string_get(fields, PFWL_FIELDS_L7_SSL_CIPHER_SUITES, &dummy2)){
#if PFWL_DEBUG_SSL
    printf("JA3 Fields: %.*s\n", ja3_last_byte - scratchpad_start, state->scratchpad + scratchpad_start);
#endif
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, state->scratchpad + scratchpad_start, ja3_last_byte - scratchpad_start);
    unsigned char md5[16];
    MD5_Final(md5, &ctx);
    int n;
    unsigned char* ja3_start = state->scratchpad + state->scratchpad_next_byte;
    for(n = 0; n < 16; n++){
      sprintf(state->scratchpad + state->scratchpad_next_byte, "%02x", md5[n]);
      state->scratchpad_next_byte += 2;
    }
#if PFWL_DEBUG_SSL
    printf("JA3: %.*s\n", 32, ja3_start);
#endif    
    pfwl_field_string_set(fields, PFWL_FIELDS_L7_SSL_JA3, ja3_start, 32);
  }
  // TODO: Everytime we write on scratchpad we should check that the max length is not exceeded
  return 2;
}

/* Code fixes courtesy of Alexsandro Brahm <alex@digistar.com.br> */
static int getSSLcertificate(pfwl_state_t* state,
                    pfwl_flow_info_private_t* flow_info_private,
                    uint32_t proc_bytes,
	                  const unsigned char* hdr,
	                  const unsigned char *payload,
                      size_t data_length,
                      char *buffer,
                      int buffer_len,
                      pfwl_field_t* fields,
                      uint32_t* next_server_extension,
                      uint32_t* remaining_extension_len) {
  /*
    Nothing matched so far: let's decode the certificate with some heuristics
    Patches courtesy of Denys Fedoryshchenko <nuclearcat@nuclearcat.com>
  */
  	size_t ssl_length = ntohs(get_u16(hdr, 3)) + 5;
    u_int8_t handshake_msg_type = hdr[5]; /* handshake protocol a bit misleading, it is message type according TLS specs */

    if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_HANDSHAKE_TYPE)){
      pfwl_field_number_set(fields, PFWL_FIELDS_L7_SSL_HANDSHAKE_TYPE, handshake_msg_type);
    }

    size_t scratchpad_start = state->scratchpad_next_byte;

    if(handshake_msg_type == SERVER_HELLO || handshake_msg_type == CLIENT_HELLO){
      if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_VERSION_HANDSHAKE) ||
         pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3)){
        uint16_t vernum = ntohs(get_u16(payload, 9));
        pfwl_field_number_set(fields, PFWL_FIELDS_L7_SSL_VERSION_HANDSHAKE, vernum);
        if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3)){
          char* ver = state->scratchpad + state->scratchpad_next_byte;
          state->scratchpad_next_byte += sprintf(ver, "%d,", vernum);
        }
      }
    }

    memset(buffer, 0, buffer_len);
      if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_CERTIFICATE) &&
         (handshake_msg_type == SERVER_HELLO || handshake_msg_type == CERTIFICATE)){
        u_int num_found = 0;

        // Here we are sure we saw the client certificate

        /* Check after handshake protocol header (5 bytes) and message header (4 bytes) */
        int i;
        int first_payload_byte = 9 - proc_bytes;
        if(first_payload_byte < 0){
        	first_payload_byte = 0;
        }
        for(i = first_payload_byte; i < data_length - 3; i++) {
          if(((payload[i] == 0x04) && (payload[i+1] == 0x03) && (payload[i+2] == 0x0c))
             || ((payload[i] == 0x04) && (payload[i+1] == 0x03) && (payload[i+2] == 0x13))
             || ((payload[i] == 0x55) && (payload[i+1] == 0x04) && (payload[i+2] == 0x03))) {
            u_int8_t server_len = payload[i+3];

            if(payload[i] == 0x55) {
              num_found++;

              if(num_found != 2) continue;
            }

            if(server_len + i + 3 < data_length) {
              char *server_name = (char*)&payload[i+4];
              u_int8_t begin = 0, len, j, num_dots;

              while(begin < server_len) {
                if(!pfwl_isprint(server_name[begin]))
                  begin++;
                else
                  break;
              }

              // len = pfwl_min(server_len-begin, buffer_len-1);
              len = buffer_len-1;
              strncpy(buffer, &server_name[begin], len);
              buffer[len] = '\0';

              /* We now have to check if this looks like an IP address or host name */
              for(j=0, num_dots = 0; j<len; j++) {
                if(!pfwl_isprint((buffer[j]))) {
                  num_dots = 0; /* This is not what we look for */
                  break;
                } else if(buffer[j] == '.') {
                  num_dots++;
                  if(num_dots >=2) break;
                }
              }

              if(num_dots >= 2) {
                stripCertificateTrailer(buffer, (int*) &buffer_len);
#if PFWL_DEBUG_SSL
      			printf("CERT: %s\n", buffer);
#endif
                // Do not set from buffer since is allocated on stack.
                pfwl_field_string_set(fields, PFWL_FIELDS_L7_SSL_CERTIFICATE, (const unsigned char*) &server_name[begin], buffer_len);
                return(1 /* Server Certificate */);
              }
            }
          }
        }
      }

      if(handshake_msg_type == CLIENT_HELLO || handshake_msg_type == SERVER_HELLO) {
        int base_offset = 43;
       	if(*next_server_extension){
       		return processExtensions(state, flow_info_private, 0, payload, *remaining_extension_len, *next_server_extension, data_length, buffer, buffer_len, fields, next_server_extension, remaining_extension_len, scratchpad_start, handshake_msg_type);
       	}
        if (base_offset + 2 <= data_length)
        {
          u_int16_t session_id_len = payload[base_offset];

          // TODO: Replace ssl_length with data_length, and if checks are not satisfied manage segmentation
          if((session_id_len+base_offset+2) <= ssl_length) {
            int offset;
            u_int16_t cypher_len;
            uint cypher_offset;
            if(handshake_msg_type == CLIENT_HELLO){
              cypher_len = ntohs(get_u16(payload, session_id_len+base_offset+1));
              offset = base_offset + session_id_len + cypher_len + 2;
              cypher_offset = base_offset + session_id_len + 3;
            }else{
              cypher_len = 2;
              offset = base_offset + session_id_len + 2;
              cypher_offset = base_offset + session_id_len + 1;
            }
#if PFWL_DEBUG_SSL
            printf("CypherLen: %d\n", cypher_len);
#endif
            if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_CIPHER_SUITES) ||
               pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3)){
              if(cypher_len){                
                char* cyphers = state->scratchpad + state->scratchpad_next_byte;
                size_t cyphers_next_char = 0;
                for(uint i = 0; i < cypher_len; i += 2){
                  uint16_t cypher_id = ntohs(get_u16(payload, cypher_offset + i));
                  if(!is_grease(cypher_id)){
                    cyphers_next_char += sprintf(cyphers + cyphers_next_char, "%d-", cypher_id);
                  }
                }
                // Remove last dash
                if(cyphers_next_char){
                  cyphers_next_char -= 1; 
                }
                sprintf(cyphers + cyphers_next_char, ",");
                state->scratchpad_next_byte += cyphers_next_char + 1; // +1 for the comma
  #if PFWL_DEBUG_SSL
                printf("Cyphers: %s\n", cyphers);
                printf("SPAD: %s\n", state->scratchpad);
  #endif    

                pfwl_field_string_set(fields, PFWL_FIELDS_L7_SSL_CIPHER_SUITES, (const unsigned char*) cyphers, cyphers_next_char);
              }else{
                sprintf(state->scratchpad + state->scratchpad_next_byte, ",");
                state->scratchpad_next_byte += 1;
              }
            }

            // Here we are sure we saw the client certificate

            if(offset < ssl_length) {
              u_int16_t compression_len;
              u_int16_t extensions_len;

              offset++;
              compression_len = payload[offset];
              offset++;

#if PFWL_DEBUG_SSL
              printf("SSL [compression_len: %u]\n", compression_len);
#endif

              // offset += compression_len + 3;
              offset += compression_len;

              if(offset < ssl_length) {
                extensions_len = ntohs(*((u_int16_t*)&payload[offset]));
                offset += 2;

#if PFWL_DEBUG_SSL
                printf("SSL [extensions_len: %u]\n", extensions_len);
#endif

				        return processExtensions(state, flow_info_private, offset, payload, extensions_len, 0, data_length, buffer, buffer_len, fields, next_server_extension, remaining_extension_len, scratchpad_start, handshake_msg_type);
              }
            }
          }
        }
      }

  return(0); /* Not found */
}

int inspectHandshake(pfwl_state_t* state,
                                    uint32_t proc_bytes,
	                                 const unsigned char* hdr,
	                                 const unsigned char *payload,
                                     size_t data_length,
                                     pfwl_flow_info_private_t* flow,
                                     pfwl_field_t* fields,
                                     uint32_t* next_server_extension,
                                     uint32_t* remaining_extension_len) {
  /* consider only specific SSL packets (handshake) */
  if(hdr[0] == 0x16 || hdr[0] == 0x17) {
    if(pfwl_protocol_field_required(state, flow, PFWL_FIELDS_L7_SSL_VERSION)){
      uint16_t vernum = ntohs(get_u16(payload, 1));
      pfwl_field_number_set(fields, PFWL_FIELDS_L7_SSL_VERSION, vernum);
    }
    char certificate[64];
    int rc;

    certificate[0] = '\0';
    rc = getSSLcertificate(state, flow, proc_bytes, hdr, payload, data_length, certificate, sizeof(certificate), fields, next_server_extension, remaining_extension_len);
    flow->ssl_information.certificate_num_checks++;
    if(rc > 0) {
      flow->ssl_information.certificates_detected++;
#if PFWL_DEBUG_SSL
      debug_print("***** [SSL] %s\n", certificate);
#endif
      // Search for known host in certificate, strlen(certificate)
      return PFWL_PROTOCOL_MATCHES;
    }

    if(flow->ssl_information.certificate_num_checks >= 2){
      return PFWL_PROTOCOL_MATCHES;
    }
  }
  return PFWL_PROTOCOL_MORE_DATA_NEEDED;
}

uint8_t check_ssl(pfwl_state_t *state, const unsigned char *payload,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private) {

  // Save first bytes
  unsigned char* hdr = flow_info_private->ssl_information.first_bytes[pkt_info->l4.direction];
  uint8_t* hdr_next = &(flow_info_private->ssl_information.next_first_bytes[pkt_info->l4.direction]);
  uint32_t* proc_bytes = &(flow_info_private->ssl_information.processed_bytes[pkt_info->l4.direction]);
  if(*hdr_next < 6){
  	size_t i = 0;
  	for(i = 0; i < data_length && i < 6 - *hdr_next; i++){
  		hdr[i + *hdr_next] = payload[i];
  	}
  	*hdr_next = i;
  	if(*hdr_next < 6){
  		*proc_bytes += data_length;
  		return PFWL_PROTOCOL_MORE_DATA_NEEDED;
  	}
  }
  *hdr_next = 0;

  debug_print("%s\n", "checking ssl...");

  if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_VERSION)                    ||
     pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_VERSION_HANDSHAKE)          ||
     pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_HANDSHAKE_TYPE)             ||
     pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_CERTIFICATE)                || 
     pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_SNI)                        ||
     pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_EXTENSIONS)                 ||
     pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES)            ||
     pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES_POINT_FMTS) ||
     pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_JA3)){
    return inspectHandshake(state, *proc_bytes, hdr, payload, data_length, flow_info_private, pkt_info->l7.protocol_fields, &(flow_info_private->ssl_information.next_server_extension), &(flow_info_private->ssl_information.remaining_extension_len));
  }

  if(flow_info_private->ssl_information.stage == 0) {
    debug_print("%s\n", "first ssl packet");
    // SSLv2 Record
    if(hdr[2] == 0x01 && hdr[3] == 0x03
       && (hdr[4] == 0x00 || hdr[4] == 0x01 || hdr[4] == 0x02)) {
      flow_info_private->ssl_information.version = PFWL_SSLV2;
      debug_print("%s\n", "SSL v2 len match");
      size_t ssl_length = hdr[1] + 2;
  	  if(ssl_length == data_length){
#if SSL_BIDIRECTIONAL
		  flow_info_private->ssl_information.stage = 1 + pkt_info->l4.direction;
	      return PFWL_PROTOCOL_MORE_DATA_NEEDED;
#else
	      return PFWL_PROTOCOL_MATCHES;
#endif
      }else if(data_length > ssl_length){
      	return PFWL_PROTOCOL_NO_MATCHES;
      }else{
      	*proc_bytes += data_length;
	  	if(*proc_bytes == ssl_length){
#if SSL_BIDIRECTIONAL
		  flow_info_private->ssl_information.stage = 1 + pkt_info->l4.direction;
	      return PFWL_PROTOCOL_MORE_DATA_NEEDED;
#else
	      return PFWL_PROTOCOL_MATCHES;
#endif
	  	}else{
  			return PFWL_PROTOCOL_MORE_DATA_NEEDED;
  		}
      }
    }

    // SSLv3 Record
    if((hdr[0] == 0x16 || hdr[0] == 0x17)
       && hdr[1] == 0x03
       && (hdr[2] == 0x00 || hdr[2] == 0x01 || hdr[2] == 0x02 || hdr[2] == 0x03)) {
      if(hdr[0] == 0x16){
        flow_info_private->ssl_information.version = PFWL_SSLV3;
        debug_print("%s\n", "SSL v3 len match");
      }else{
        flow_info_private->ssl_information.version = PFWL_TLSV1_2;
        debug_print("%s\n", "TLS v1.2 len match");
      }
      size_t ssl_length = ntohs(get_u16(hdr, 3)) + 5;
  	  if(ssl_length == data_length){
#if SSL_BIDIRECTIONAL
		  flow_info_private->ssl_information.stage = 1 + pkt_info->l4.direction;
	      return PFWL_PROTOCOL_MORE_DATA_NEEDED;
#else
	      return PFWL_PROTOCOL_MATCHES;
#endif
	  }else if(data_length > ssl_length){
      	return PFWL_PROTOCOL_NO_MATCHES;
      }else{
	  	*proc_bytes += data_length;
	  	if(*proc_bytes == ssl_length){
#if SSL_BIDIRECTIONAL
		  flow_info_private->ssl_information.stage = 1 + pkt_info->l4.direction;
	      return PFWL_PROTOCOL_MORE_DATA_NEEDED;
#else
	      return PFWL_PROTOCOL_MATCHES;
#endif
	  	}else{
  			return PFWL_PROTOCOL_MORE_DATA_NEEDED;
  		}
	  }
    }
  }

#if SSL_BIDIRECTIONAL
  if(flow_info_private->ssl_information.stage != 0) {
      if(hdr[2] == 0x01 && hdr[3] == 0x03
         && (hdr[4] == 0x00 || hdr[4] == 0x01 || hdr[4] == 0x02) 
         && flow_info_private->ssl_information.version == PFWL_SSLV2){
      	return PFWL_PROTOCOL_MATCHES;
      }

      if((hdr[0] == 0x16 || hdr[0] == 0x17)
         && hdr[1] == 0x03
         && (hdr[2] == 0x00 || hdr[2] == 0x01 || hdr[2] == 0x02 || hdr[2] == 0x03)) {
      	if((flow_info_private->ssl_information.version == PFWL_SSLV3 && hdr[0] == 0x16) ||
      	   (flow_info_private->ssl_information.version == PFWL_TLSV1_2 && hdr[0] == 0x17)){
      		return PFWL_PROTOCOL_MATCHES;
		}
      }

  }
#endif

  debug_print("%s\n", "ssl doesn't match");
  return PFWL_PROTOCOL_NO_MATCHES;
}
