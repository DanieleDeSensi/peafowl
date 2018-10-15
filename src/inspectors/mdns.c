/*
 * mdns.c
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

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define PFWL_MDNS_IPv4_DEST_ADDRESS 0xFB0000E0
#elif __BYTE_ORDER == __BIG_ENDIAN
#define PFWL_MDNS_IPv4_DEST_ADDRESS 0xE00000FB
#else
#error "Please fix <bits/endian.h>"
#endif

const struct in6_addr PFWL_MDNS_IPV6_DEST_ADDRESS = {
    .s6_addr = {0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0xFB}};

uint8_t check_mdns(pfwl_state_t *state, const unsigned char *app_data,
                   size_t data_length, pfwl_dissection_info_t *pkt_info,
                   pfwl_flow_info_private_t *flow_info_private) {
  if (pkt_info->l4.port_dst == port_mdns && data_length >= 12) {
    if (pkt_info->l3.protocol == PFWL_PROTO_L3_IPV4 &&
        pkt_info->l3.addr_dst.ipv4 == PFWL_MDNS_IPv4_DEST_ADDRESS) {
      return PFWL_PROTOCOL_MATCHES;
    } else if (pkt_info->l3.protocol == PFWL_PROTO_L3_IPV6 &&
               pfwl_v6_addresses_equal(pkt_info->l3.addr_dst.ipv6,
                                       PFWL_MDNS_IPV6_DEST_ADDRESS)) {
      return PFWL_PROTOCOL_MATCHES;
    }
  }
  return PFWL_PROTOCOL_NO_MATCHES;
}
