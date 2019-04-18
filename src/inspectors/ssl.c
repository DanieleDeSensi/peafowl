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

#include <stdio.h>

#define PFWL_DEBUG_SSL 0
#define debug_print(fmt, ...)                                                  \
  do {                                                                         \
  if (PFWL_DEBUG_SSL)                                                        \
  fprintf(stdout, fmt, __VA_ARGS__);                                       \
  } while (0)


// #define CERTIFICATE_DEBUG 1
#define PFWL_MAX_SSL_REQUEST_SIZE 10000

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

/* Code fixes courtesy of Alexsandro Brahm <alex@digistar.com.br> */
int getSSLcertificate(const unsigned char *payload,
                      size_t data_length,
                      char *buffer,
                      int buffer_len,
                      pfwl_field_t* fields) {
#ifdef CERTIFICATE_DEBUG
  {
    static u_int8_t id = 0;

    debug_print("-> [%u] %02X\n", ++id, payload[0] & 0xFF);
  }
#endif

  /*
    Nothing matched so far: let's decode the certificate with some heuristics
    Patches courtesy of Denys Fedoryshchenko <nuclearcat@nuclearcat.com>
  */
  if(payload[0] == 0x16 /* Handshake */) {
    u_int16_t total_len  = (payload[3] << 8) + payload[4] + 5 /* SSL Header */;
    u_int8_t handshake_protocol = payload[5]; /* handshake protocol a bit misleading, it is message type according TLS specs */

    memset(buffer, 0, buffer_len);

    /* Truncate total len, search at least in incomplete packet */
    if(total_len > data_length)
      total_len = data_length;

    /* At least "magic" 3 bytes, null for string end, otherwise no need to waste cpu cycles */
    if(total_len > 4) {
      if(handshake_protocol == 0x02 || handshake_protocol == 0xb /* Server Hello and Certificate message types are interesting for us */) {
        u_int num_found = 0;

        // Here we are sure we saw the client certificate

        /* Check after handshake protocol header (5 bytes) and message header (4 bytes) */
        int i;
        for(i = 9; i < data_length-3; i++) {
          if(((payload[i] == 0x04) && (payload[i+1] == 0x03) && (payload[i+2] == 0x0c))
             || ((payload[i] == 0x04) && (payload[i+1] == 0x03) && (payload[i+2] == 0x13))
             || ((payload[i] == 0x55) && (payload[i+1] == 0x04) && (payload[i+2] == 0x03))) {
            u_int8_t server_len = payload[i+3];

            if(payload[i] == 0x55) {
              num_found++;

              if(num_found != 2) continue;
            }

            if(server_len+i+3 < data_length) {
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
                // Do not set from buffer since is allocated on stack.
                pfwl_field_string_set(fields, PFWL_FIELDS_L7_SSL_CERTIFICATE, (const unsigned char*) &server_name[begin], buffer_len);
                return(1 /* Server Certificate */);
              }
            }
          }
        }
      } else if(handshake_protocol == 0x01 /* Client Hello */) {
        u_int offset, base_offset = 43;
        if (base_offset + 2 <= data_length)
        {
          u_int16_t session_id_len = payload[base_offset];

          if((session_id_len+base_offset+2) <= total_len) {
            u_int16_t cypher_len =  payload[session_id_len+base_offset+2] + (payload[session_id_len+base_offset+1] << 8);
            offset = base_offset + session_id_len + cypher_len + 2;

            // Here we are sure we saw the client certificate

            if(offset < total_len) {
              u_int16_t compression_len;
              u_int16_t extensions_len;

              offset++;
              compression_len = payload[offset];
              offset++;

#ifdef CERTIFICATE_DEBUG
              printf("SSL [compression_len: %u]\n", compression_len);
#endif

              // offset += compression_len + 3;
              offset += compression_len;

              if(offset < total_len) {
                extensions_len = ntohs(*((u_int16_t*)&payload[offset]));
                offset += 2;

#ifdef CERTIFICATE_DEBUG
                printf("SSL [extensions_len: %u]\n", extensions_len);
#endif

                if((extensions_len+offset) <= total_len) {
                  /* Move to the first extension
           Type is u_int to avoid possible overflow on extension_len addition */
                  u_int extension_offset = 0;

                  while(extension_offset < extensions_len) {
                    u_int16_t extension_id, extension_len;

                    extension_id = ntohs(*((u_int16_t*)&payload[offset+extension_offset]));
                    extension_offset += 2;

                    extension_len = ntohs(*((u_int16_t*)&payload[offset+extension_offset]));
                    extension_offset += 2;

#ifdef CERTIFICATE_DEBUG
                    printf("SSL [extension_id: %u][extension_len: %u]\n", extension_id, extension_len);
#endif

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
                      // Do not set from buffer since is allocated on stack.
                      pfwl_field_string_set(fields, PFWL_FIELDS_L7_SSL_SNI, (const unsigned char*) &server_name[begin], buffer_len);
                      /* We're happy now */
                      return(2 /* Client Certificate */);
                    }

                    extension_offset += extension_len;
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  return(0); /* Not found */
}

int sslDetectProtocolFromCertificate(const unsigned char *payload,
                                     size_t data_length,
                                     pfwl_flow_info_private_t* flow,
                                     pfwl_field_t* fields) {
  if((data_length > 9) &&
     (payload[0] == 0x16 /* consider only specific SSL packets (handshake) */)) {
    char certificate[64];
    int rc;

    certificate[0] = '\0';
    rc = getSSLcertificate(payload, data_length, certificate, sizeof(certificate), fields);
    flow->ssl_information.certificate_num_checks++;

    if(rc > 0) {
      flow->ssl_information.certificates_detected++;
#ifdef CERTIFICATE_DEBUG
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

static u_int8_t pfwl_search_sslv3_direction1(const unsigned char *payload,
                                             size_t data_length,
                                             pfwl_flow_info_private_t* flow) {

  if(flow->ssl_information.version == PFWL_SSLV3) {
    u_int32_t temp;
    debug_print("%s\n", "search sslv3");
    // SSLv3 Record
    if(data_length >= 1300) {
      return 1;
    }
    temp = ntohs(get_u16(payload, 3)) + 5;
    debug_print("temp = %u\n", temp);
    if(data_length == temp ||
       (temp < data_length && data_length > 500)) {
      return 1;
    }

    if(data_length < temp && temp < 5000 && data_length > 9) {
      /* the server hello may be split into small packets */
      u_int32_t cert_start;
      debug_print("%s\n", "maybe SSLv3 server hello split into smaller packets");
      /* lets hope at least the server hello and the start of the certificate block are in the first packet */
      cert_start = ntohs(get_u16(payload, 7)) + 5 + 4;
      debug_print("suspected start of certificate: %u\n", cert_start);

      if(cert_start < data_length &&
         payload[cert_start] == 0x0b) {
        debug_print("%s\n", "found 0x0b at suspected start of certificate block");
        return 2;
      }
    }

    if((data_length > temp && data_length > 100) &&
       data_length > 9) {
      /* the server hello may be split into small packets and the certificate has its own SSL Record
       * so temp contains only the length for the first ServerHello block */
      u_int32_t cert_start;

      debug_print("%s\n", "maybe SSLv3 server hello split into smaller packets but with seperate record for the certificate");

      /* lets hope at least the server hello record and the start of the certificate record are in the first packet */
      cert_start = ntohs(get_u16(payload, 7)) + 5 + 5 + 4;
      debug_print("suspected start of certificate: %u\n", cert_start);

      if(cert_start < data_length &&
         payload[cert_start] == 0x0b) {
        debug_print("%s\n", "found 0x0b at suspected start of certificate block");
        return 2;
      }
    }


    if(data_length >= temp + 5 &&
       (payload[temp] == 0x14 || payload[temp] == 0x16) &&
       payload[temp + 1] == 0x03) {
      u_int32_t temp2 = ntohs(get_u16(payload, temp + 3)) + 5;
      if(temp + temp2 > PFWL_MAX_SSL_REQUEST_SIZE) {
        return 1;
      }
      temp += temp2;
      debug_print("temp = %u\n", temp);
      if(data_length == temp) {
        return 1;
      }
      if(data_length >= temp + 5 &&
         payload[temp] == 0x16 &&
         payload[temp + 1] == 0x03) {
        temp2 = ntohs(get_u16(payload, temp + 3)) + 5;
        if(temp + temp2 > PFWL_MAX_SSL_REQUEST_SIZE) {
          return 1;
        }
        temp += temp2;
        debug_print("temp = %u\n", temp);
        if(data_length == temp) {
          return 1;
        }
        if(data_length >= temp + 5 &&
           payload[temp] == 0x16 &&
           payload[temp + 1] == 0x03) {
          temp2 = ntohs(get_u16(payload, temp + 3)) + 5;
          if(temp + temp2 > PFWL_MAX_SSL_REQUEST_SIZE) {
            return 1;
          }
          temp += temp2;
          debug_print("temp = %u\n", temp);
          if(temp == data_length) {
            return 1;
          }
        }
      }
    }
  }

  return 0;
}

uint8_t check_ssl(pfwl_state_t *state, const unsigned char *payload,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private) {
  if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_CERTIFICATE) || 
     pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_SSL_SNI)){
    if(sslDetectProtocolFromCertificate(payload, data_length, flow_info_private, pkt_info->l7.protocol_fields) == PFWL_PROTOCOL_MATCHES){
      return PFWL_PROTOCOL_MATCHES;
    }
  }

  if(data_length > 40 && flow_info_private->ssl_information.stage == 0) {
    debug_print("%s\n", "first ssl packet");
    // SSLv2 Record
    if(payload[2] == 0x01 && payload[3] == 0x03
       && (payload[4] == 0x00 || payload[4] == 0x01 || payload[4] == 0x02)
       && (data_length - payload[1] == 2)) {
      flow_info_private->ssl_information.version = PFWL_SSLV2;
      debug_print("%s\n", "sslv2 len match");
      flow_info_private->ssl_information.stage = 1 + pkt_info->l4.direction;
      return PFWL_PROTOCOL_MATCHES;
    }

    // SSLv3 Record
    if(payload[0] == 0x16 && payload[1] == 0x03
       && (payload[2] == 0x00 || payload[2] == 0x01 || payload[2] == 0x02 || payload[2] == 0x03)
       && (data_length - ntohs(get_u16(payload, 3)) == 5)) {
      flow_info_private->ssl_information.version = PFWL_SSLV3;
      debug_print("%s\n", "sslv3 len match");
      flow_info_private->ssl_information.stage = 1 + pkt_info->l4.direction;
      return PFWL_PROTOCOL_MATCHES;
    }
  }

  if(data_length > 40 &&
     flow_info_private->ssl_information.stage == 1 + pkt_info->l4.direction &&
     flow_info_private->info_public->statistics[PFWL_STAT_L7_PACKETS][pkt_info->l4.direction] < 5) {
    return PFWL_PROTOCOL_MATCHES;
  }

  if(data_length > 40 && flow_info_private->ssl_information.stage == 2 - pkt_info->l4.direction) {
    debug_print("%s\n", "second ssl packet");
    // SSLv2 Record
    if(flow_info_private->ssl_information.version == PFWL_SSLV2 &&
       (data_length - 2) >= payload[1]) {
      debug_print("%s\n", "sslv2 server len match");
      return PFWL_PROTOCOL_MATCHES;
    }

    uint8_t ret = pfwl_search_sslv3_direction1(payload, data_length, flow_info_private);
    if(ret == 1) {
      debug_print("%s\n", "sslv3 server len match");
      return PFWL_PROTOCOL_MATCHES;
    } else if(ret == 2) {
      debug_print("%s\n", "sslv3 server len match with split packet -> check some more packets for SSL patterns");
      flow_info_private->ssl_information.stage = 3;
      return PFWL_PROTOCOL_MATCHES;
    }

    if(data_length > 40 &&
       flow_info_private->info_public->statistics[PFWL_STAT_L7_PACKETS][pkt_info->l4.direction] < 5) {
      debug_print("%s\n", "ssl more data needed");
      return PFWL_PROTOCOL_MORE_DATA_NEEDED;
    }
  }
  debug_print("%s\n", "ssl doesn't match");
  return PFWL_PROTOCOL_NO_MATCHES;
}
