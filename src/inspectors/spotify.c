/*
 * spotify.c
 *
 * This protocol inspector is adapted from
 * the nDPI Spotify dissector
 * (https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/spotify.c)
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

uint8_t check_spotify(pfwl_state_t *state, const unsigned char *app_data,
                      size_t data_length, pfwl_dissection_info_t *pkt_info,
                      pfwl_flow_info_private_t *flow_info_private) {
  if (pkt_info->l4.protocol == IPPROTO_UDP) {
    if (pkt_info->l4.port_src == port_spotify &&
        pkt_info->l4.port_dst == port_spotify && data_length >= 7) {
      if (memcmp(app_data, "SpotUdp", 7) == 0) {
        return PFWL_PROTOCOL_MATCHES;
      }
    }
  } else if (pkt_info->l4.protocol == IPPROTO_TCP) {
    if (data_length >= 9 && app_data[0] == 0x00 && app_data[1] == 0x04 &&
        app_data[2] == 0x00 && app_data[3] == 0x00 && app_data[6] == 0x52 &&
        (app_data[7] == 0x0e || app_data[7] == 0x0f) && app_data[8] == 0x50) {
      return PFWL_PROTOCOL_MATCHES;
    } else if (pkt_info->l3.protocol ==
               PFWL_PROTO_L3_IPV4) { /* IPv4 Only: we need to support
                                        packet->iphv6 at some point */
      /*
        Spotify
        78.31.8.0 - 78.31.15.255 (78.31.8.0/22)
        AS29017
        193.235.232.0 - 193.235.235.255 (193.235.232.0/22)
        AS29017
        194.132.196.0 - 194.132.199.255 (194.132.198.147/22)
        AS43650
        194.132.176.0 - 194.132.179.255  (194.132.176.0/22)
        AS43650
        194.132.162.0 - 194.132.163.255   (194.132.162.0/24)
        AS43650
      */
      long src_addr = ntohl(pkt_info->l3.addr_src.ipv4);
      long dst_addr = ntohl(pkt_info->l3.addr_dst.ipv4);
      long src_addr_masked_22 = src_addr & 0xFFFFFC00; // */22
      long dst_addr_masked_22 = dst_addr & 0xFFFFFC00; // */22
      long src_addr_masked_24 = src_addr & 0xFFFFFF00; // */24
      long dst_addr_masked_24 = dst_addr & 0xFFFFFF00; // */24
      if (src_addr_masked_22 == 0x4E1F0800 ||          /* 78.31.8.0/22 */
          dst_addr_masked_22 == 0x4E1F0800 ||
          /* 193.235.232.0/22 */
          src_addr_masked_22 == 0xC1EBE800 ||
          dst_addr_masked_22 == 0xC1EBE800 ||
          /* 194.132.196.0/22 */
          src_addr_masked_22 == 0xC284C400 ||
          dst_addr_masked_22 == 0xC284C400 ||
          /* 194.132.176.0/22 */
          src_addr_masked_22 == 0xC284B000 ||
          dst_addr_masked_22 == 0xC284B000 ||
          /* 194.132.162.0/24 */
          src_addr_masked_24 == 0xC284A200 ||
          dst_addr_masked_24 == 0xC284A200) {
        return PFWL_PROTOCOL_MATCHES;
      }
    }
  }
  return PFWL_PROTOCOL_NO_MATCHES;
}
