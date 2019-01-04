/*
 * quic.c
 *
 * Protocol specification: https://tools.ietf.org/html/draft-tsvwg-quic-protocol-00
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

#define PFWL_DEBUG_DISS_QUIC 0
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

static size_t convert_length_sequence(size_t len){
  switch(len){
    case 0x30:
      return 6;
    case 0x20:
      return 4;
    case 0x10:
      return 2;
    case 0x00:
      return 1;
    default:
      return 0;
  }
}

static uint16_t quic_getu16(const unsigned char* start, size_t offset, const unsigned char* version_start){
#if __BYTE_ORDER == __LITTLE_ENDIAN
  return get_u16((const char*) start, offset);
#elif __BYTE_ORDER == __BIG_ENDIAN
  uint16_t x = get_u16((const char*) start, offset);
  return x << 8 | x >> 8;
#else
#error "Please fix <bits/endian.h>"
#endif
}

static uint32_t quic_getu32(const unsigned char* start, size_t offset, const unsigned char* version_start){
  //int version = atoi((const char*) version_start + 1);
#if __BYTE_ORDER == __LITTLE_ENDIAN
  return get_u32((const char*) start, offset);
#elif __BYTE_ORDER == __BIG_ENDIAN
  uint32_t x = get_u32((const char*) start, offset);
  return ((((x) & 0xff000000u) >> 24) | (((x) & 0x00ff0000u) >> 8) | (((x) & 0x0000ff00u) << 8) | (((x) & 0x000000ffu) << 24));
#else
#error "Please fix <bits/endian.h>"
#endif
}

uint8_t check_quic(pfwl_state_t *state, const unsigned char *app_data,
                     size_t data_length, pfwl_dissection_info_t *pkt_info,
                     pfwl_flow_info_private_t *flow_info_private){
  if(data_length >= 2){
    size_t connection_id_len = convert_length_connection(app_data[0] & 0x0C);
    size_t unused_bits = app_data[0] & 0xC0;
    int has_version = app_data[0] & 0x01;
    if(unused_bits == 0 &&
       connection_id_len == 8){ // Must be 8 for the first packets
      if(has_version &&
         app_data[connection_id_len + 1] != 'Q'){
        return PFWL_PROTOCOL_NO_MATCHES;
      }
      const unsigned char* version_start = app_data + connection_id_len + 1;
      if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_QUIC_VERSION)){
        pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_VERSION, version_start, 4);
      }

      if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_QUIC_SNI)){
        debug_print("%s\n", "Searching for SNI");
        size_t sequence_len = convert_length_sequence(app_data[0] & 0x30);
        size_t header_estimation = 1 + connection_id_len + (has_version?4:0) + sequence_len;
        const unsigned char* chlo_start = (const unsigned char*) pfwl_strnstr((const char*) app_data + header_estimation, "CHLO", data_length - header_estimation);
        if(chlo_start){
          debug_print("%s\n", "CHLO found");
          uint16_t num_tags = quic_getu16(chlo_start, 4, version_start);
          size_t start_tags = ((const unsigned char*) chlo_start - app_data) + 8;
          size_t start_content = start_tags + num_tags*8;
          debug_print("Num tags: %d\n", num_tags);
          u_int32_t last_offset_end = 0;
          for(size_t i = start_tags; i < data_length; i += 8){
            if(app_data[i]     == 'S' &&
               app_data[i + 1] == 'N' &&
               app_data[i + 2] == 'I' &&
               app_data[i + 3] == 0){
              u_int32_t offset_end = quic_getu32(app_data, i + 4, version_start);
              debug_print("Offset end: %d Last offset end: %d\n", offset_end, last_offset_end);
              u_int32_t length = offset_end - last_offset_end;
              u_int32_t offset = last_offset_end;
              if(start_content + offset + length  <= data_length){
                pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_SNI, app_data + start_content + offset, length);
                debug_print("Found SNI with length %d: %.*s\n", length, (int) length, app_data + start_content + offset);
                break;
              }
            }
            last_offset_end = quic_getu32(app_data, i + 4, version_start);
          }
        }
      }
      return PFWL_PROTOCOL_MATCHES;
    }
  }
  return PFWL_PROTOCOL_NO_MATCHES;
}
