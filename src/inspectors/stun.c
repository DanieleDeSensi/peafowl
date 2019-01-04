/*
 * stun.c
 *
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 * Copyright (c) 2018-2019 Michele Campus (michelecampus5@gmail.com)
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
#include <peafowl/flow_table.h>
#include <peafowl/inspectors/inspectors.h>
#include <peafowl/peafowl.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define STUN_MAGIC_COOKIE 0x42A41221
#define STUN_MAPPED_ADDRESS 0x0100
#define STUN_XOR_MAPPED_ADDRESS 0x2000
#elif __BYTE_ORDER == __BIG_ENDIAN
#define STUN_MAGIC_COOKIE 0x2112A442
#define STUN_MAPPED_ADDRESS 0x0001
#define STUN_XOR_MAPPED_ADDRESS 0x0020
#else
#error "Please fix <bits/endian.h>"
#endif

struct stun_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
  uint16_t msg_type : 14;
  uint8_t zeros : 2;
#elif __BYTE_ORDER == __BIG_ENDIAN
  uint8_t zeros : 2;
  uint16_t msg_type : 14;
#endif
  uint16_t msg_len;
  uint32_t magic_cookie;
  uint32_t transaction_id_0;
  uint32_t transaction_id_1;
  uint32_t transaction_id_2;
} __attribute__((packed));

uint8_t check_stun(pfwl_state_t *state, const unsigned char *app_data,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private) {
  struct stun_header* stun_packet = (struct stun_header*) app_data;
  if(stun_packet->zeros == 0 &&
     stun_packet->magic_cookie == STUN_MAGIC_COOKIE){
    if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_STUN_MAPPED_ADDRESS)      ||
       pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_STUN_MAPPED_ADDRESS_PORT)){
      size_t offset = sizeof(struct stun_header);
      while(offset < data_length){
        uint16_t type = get_u16(app_data, offset);
        uint16_t length = ntohs(get_u16(app_data, offset + 2));
        if(type == STUN_MAPPED_ADDRESS ||
           type == STUN_XOR_MAPPED_ADDRESS){
          uint8_t family = app_data[offset + 5];
          uint16_t port = ntohs(get_u16(app_data, offset + 6));
          size_t addr_len = 0;
          if(family == 0x01){
            // IPv4
            addr_len = 4;
            struct in_addr in;
            in.s_addr = get_u32(app_data, offset + 8);
            if(type == STUN_XOR_MAPPED_ADDRESS){
              in.s_addr ^= STUN_MAGIC_COOKIE;
            }
            inet_ntop(AF_INET, &in, flow_info_private->stun_mapped_address, sizeof(flow_info_private->stun_mapped_address));
          }else{
            // IPv6
            addr_len = 16;
            struct in6_addr in;
            memcpy(in.__in6_u.__u6_addr8, app_data + offset + 8, 16);
            if(type == STUN_XOR_MAPPED_ADDRESS){
              in.__in6_u.__u6_addr32[0] ^= STUN_MAGIC_COOKIE;
              in.__in6_u.__u6_addr32[1] ^= stun_packet->transaction_id_0;
              in.__in6_u.__u6_addr32[2] ^= stun_packet->transaction_id_1;
              in.__in6_u.__u6_addr32[3] ^= stun_packet->transaction_id_2;
            }
            inet_ntop(AF_INET6, &in, flow_info_private->stun_mapped_address, sizeof(flow_info_private->stun_mapped_address));
          }
          if(type == STUN_XOR_MAPPED_ADDRESS){
#if __BYTE_ORDER == __LITTLE_ENDIAN
            port ^= 0x2112;
#else
            port ^= 0x1221;
#endif
          }
          pfwl_field_number_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_STUN_MAPPED_ADDRESS_PORT, port);
          pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_STUN_MAPPED_ADDRESS, (const unsigned char*) flow_info_private->stun_mapped_address, addr_len);
        }
        offset += length + 4; /* 'Type' and 'length' lengths are not included in 'length'*/
      }
    }
    return PFWL_PROTOCOL_MATCHES;
  }else{
    return PFWL_PROTOCOL_NO_MATCHES;
  }
}
