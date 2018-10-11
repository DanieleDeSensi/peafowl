/*
 * ssl.c
 *
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
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

/**
 * Created by max197616 (https://github.com/max197616) and based on
 * nDPI's SSL dissector.
 **/
#include <peafowl/peafowl.h>
#include <peafowl/flow_table.h>
#include <peafowl/inspectors/inspectors.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PFWL_DEBUG_SSL 0
#define debug_print(fmt, ...)                             \
  do {                                                    \
    if (PFWL_DEBUG_SSL) fprintf(stdout, fmt, __VA_ARGS__); \
  } while (0)

#define npfwl_isalpha(ch) \
  (((ch) >= 'a' && (ch) <= 'z') || ((ch) >= 'A' && (ch) <= 'Z'))
#define npfwl_isdigit(ch) ((ch) >= '0' && (ch) <= '9')
#define npfwl_isspace(ch) (((ch) >= '\t' && (ch) <= '\r') || ((ch) == ' '))
#define npfwl_isprint(ch) ((ch) >= 0x20 && (ch) <= 0x7e)
#define npfwl_ispunct(ch)                                           \
  (((ch) >= '!' && (ch) <= '/') || ((ch) >= ':' && (ch) <= '@') || \
   ((ch) >= '[' && (ch) <= '`') || ((ch) >= '{' && (ch) <= '~'))

static int getSSLcertificate(uint8_t* payload, u_int payload_len,
                             pfwl_dissection_info_t* t,
                             pfwl_inspector_accuracy_t accuracy,
                             uint8_t *required_fields) {
  if (payload[0] == 0x16 /* Handshake */) {
    uint16_t total_len = (payload[3] << 8) + payload[4] + 5 /* SSL Header */;
    uint8_t handshake_protocol = payload[5]; /* handshake protocol a bit
                                                misleading, it is message type
                                                according TLS specs */

    if (total_len <= 4) return 0;

    if (total_len > payload_len) {
      if (handshake_protocol == 0x01) {
        return 3;  // need more data
      } else {
        return 0;
      }
    }

    if (handshake_protocol == 0x02 || handshake_protocol == 0xb) {
      u_int num_found = 0;
      // Check after handshake protocol header (5 bytes) and message header (4
      // bytes)
      for (int i = 9; i < payload_len - 3; i++) {
        if (((payload[i] == 0x04) && (payload[i + 1] == 0x03) &&
             (payload[i + 2] == 0x0c)) ||
            ((payload[i] == 0x04) && (payload[i + 1] == 0x03) &&
             (payload[i + 2] == 0x13)) ||
            ((payload[i] == 0x55) && (payload[i + 1] == 0x04) &&
             (payload[i + 2] == 0x03))) {
          uint8_t server_len = payload[i + 3];
          if (payload[i] == 0x55) {
            num_found++;
            if (num_found != 2) continue;
          }
          if (server_len + i + 3 < payload_len) {
            unsigned char* server_name = (unsigned char*) &payload[i + 4];
            uint8_t begin = 0, j, num_dots, len;
            while (begin < server_len) {
              if (!npfwl_isprint(server_name[begin]))
                begin++;
              else
                break;
            }
            len = server_len - begin;
            for (j = begin, num_dots = 0; j < len; j++) {
              if (!npfwl_isprint((server_name[j]))) {
                num_dots = 0;  // This is not what we look for
                break;
              } else if (server_name[j] == '.') {
                num_dots++;
                if (num_dots >= 2) break;
              }
            }
            if (num_dots >= 2) {
              if (len > 0 && required_fields[PFWL_FIELDS_SSL_CERTIFICATE]) {
                  pfwl_field_string_set(t->l7.protocol_fields, PFWL_FIELDS_SSL_CERTIFICATE , &server_name[begin], len);
              }
              return 2;
            }
          }
        }
      }
      return 4;
    } else if (handshake_protocol == 0x01) {
      u_int offset, base_offset = 43;
      if (base_offset + 2 <= payload_len) {
        uint16_t session_id_len = payload[base_offset];
        if ((session_id_len + base_offset + 2) <= total_len) {
          uint16_t cypher_len =
              payload[session_id_len + base_offset + 2] +
              (payload[session_id_len + base_offset + 1] << 8);
          offset = base_offset + session_id_len + cypher_len + 2;
          if (offset < total_len) {
            uint16_t compression_len;
            compression_len = payload[offset + 1];
            offset += compression_len + 3;
            if (offset < total_len) {
              uint16_t extensions_len = payload[offset];
              if ((extensions_len + offset) < total_len) {
                /* Move to the first extension
                Type is u_int to avoid possible overflow on extension_len
                addition */
                u_int extension_offset = 1;
                while (extension_offset < extensions_len) {
                  uint16_t extension_id =
                      (payload[offset + extension_offset] << 8) +
                      payload[offset + extension_offset + 1];
                  extension_offset += 2;
                  uint16_t extension_len =
                      (payload[offset + extension_offset] << 8) +
                      payload[offset + extension_offset + 1];
                  extension_offset += 2;
                  if (extension_len > total_len) /* bad ssl */
                    return 0;
                  if (extension_id == 0) {
                    u_int begin = 0, len;
                    unsigned char* server_name =
                        (unsigned char*)&payload[offset + extension_offset];
                    if (payload[offset + extension_offset + 2] ==
                        0x00)  // host_name
                      begin = +5;
                    while (begin < extension_len) {
                      if ((!npfwl_isprint(server_name[begin])) ||
                          npfwl_ispunct(server_name[begin]) ||
                          npfwl_isspace(server_name[begin]))
                        begin++;
                      else
                        break;
                    }
                    len = extension_len - begin;
                    if (len > total_len) {
                      return 0; /* bad ssl */
                    }
                    if (len > 0 && required_fields[PFWL_FIELDS_SSL_CERTIFICATE]) {
                        pfwl_field_string_set(t->l7.protocol_fields, PFWL_FIELDS_SSL_CERTIFICATE , &server_name[begin], len);
                    }
                    return 2;
                  }
                  extension_offset += extension_len;
                }
                return 4;  // SSL, but no certificate
              }
            }
          }
        }
      }
    }
  }
  return 0;
}

static int detectSSLFromCertificate(uint8_t* payload, int payload_len,
                                    pfwl_dissection_info_t* t,
                                    pfwl_inspector_accuracy_t accuracy,
                                    uint8_t *required_fields) {
  if ((payload_len > 9) &&
      (payload[0] ==
       0x16 /* consider only specific SSL packets (handshake) */)) {
    int rc = getSSLcertificate(payload, payload_len, t, accuracy, required_fields);
    if (rc > 0) {
      return rc;
    }
  }
  return 0;
}

uint8_t check_ssl(pfwl_state_t* state,
                  const unsigned char* payload,
                  size_t data_length,
                  pfwl_dissection_info_t* pkt_info,
                  pfwl_flow_info_private_t* flow_info_private) {
  if (pkt_info->l4.protocol != IPPROTO_TCP) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }
  pfwl_inspector_accuracy_t accuracy = state->inspectors_accuracy[PFWL_PROTOCOL_SSL];
  uint8_t* required_fields = state->fields_to_extract;
  int res;
  debug_print("Checking ssl with size %ld, direction %d\n", data_length,
              pkt_info->l4.direction);
  if (flow_info_private->ssl_information[pkt_info->l4.direction].pkt_buffer == NULL) {
    res = detectSSLFromCertificate((uint8_t*)payload, data_length,
                                   pkt_info, accuracy, required_fields);
    debug_print("Result %d\n", res);
    if (res > 0) {
      if (res == 3) {
        flow_info_private->ssl_information[pkt_info->l4.direction].pkt_buffer =
            (uint8_t*)malloc(data_length);
        memcpy(flow_info_private->ssl_information[pkt_info->l4.direction].pkt_buffer, payload,
               data_length);
        flow_info_private->ssl_information[pkt_info->l4.direction].pkt_size = data_length;
        return PFWL_PROTOCOL_MORE_DATA_NEEDED;
      }
      return PFWL_PROTOCOL_MATCHES;
    }
  } else {
    flow_info_private->ssl_information[pkt_info->l4.direction].pkt_buffer = (uint8_t*)realloc(
        flow_info_private->ssl_information[pkt_info->l4.direction].pkt_buffer,
        flow_info_private->ssl_information[pkt_info->l4.direction].pkt_size + data_length);
    memcpy(flow_info_private->ssl_information[pkt_info->l4.direction].pkt_buffer +
               flow_info_private->ssl_information[pkt_info->l4.direction].pkt_size,
           payload, data_length);
    flow_info_private->ssl_information[pkt_info->l4.direction].pkt_size += data_length;
    res =
        detectSSLFromCertificate(flow_info_private->ssl_information[pkt_info->l4.direction].pkt_buffer,
                                 flow_info_private->ssl_information[pkt_info->l4.direction].pkt_size,
                                 pkt_info, accuracy, required_fields);
    debug_print("Checked %d bytes and result %d\n",
                flow_info_private->ssl_information[pkt_info->l4.direction].pkt_size, res);
    if (res > 0) {
      if (res == 3) {
        return PFWL_PROTOCOL_MORE_DATA_NEEDED;
      }
      return PFWL_PROTOCOL_MATCHES;
    }
  }
  return PFWL_PROTOCOL_NO_MATCHES;
}
