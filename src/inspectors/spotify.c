/*
 * spotify.c
 *
 * This protocol inspector is adapted from
 * the nDPI Spotify dissector
 (https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/spotify.c)
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
#include <peafowl/inspectors/inspectors.h>
#include <peafowl/peafowl.h>

uint8_t check_spotify(const unsigned char* app_data, uint32_t data_length, pfwl_identification_result_t* pkt_info,
                      pfwl_tracking_informations_t* tracking_info, pfwl_inspector_accuracy_t accuracy, uint8_t *required_fields) {
  if (pkt_info->protocol_l4 == IPPROTO_UDP) {
    if (pkt_info->port_src == port_spotify &&
        pkt_info->port_dst == port_spotify &&
        data_length >= 7) {
      if (memcmp(app_data, "SpotUdp", 7) == 0) {
        return PFWL_PROTOCOL_MATCHES;
      }
    }
  } else if (pkt_info->protocol_l4 == IPPROTO_TCP) {
    if (data_length >= 9 && app_data[0] == 0x00 &&
        app_data[1] == 0x04 && app_data[2] == 0x00 &&
        app_data[3] == 0x00 && app_data[6] == 0x52 &&
        (app_data[7] == 0x0e || app_data[7] == 0x0f) &&
        app_data[8] == 0x50) {
      return PFWL_PROTOCOL_MATCHES;
    } else if (pkt_info->ip_version == 4) { /* IPv4 Only: we need to support packet->iphv6 at some point */
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
      long src_addr = ntohl(pkt_info->addr_src.ipv4);
      long dst_addr = ntohl(pkt_info->addr_dst.ipv4);
      long src_addr_masked_22 = src_addr & 0xFFFFFC00; // */22
      long dst_addr_masked_22 = dst_addr & 0xFFFFFC00; // */22
      long src_addr_masked_24 = src_addr & 0xFFFFFF00; // */24
      long dst_addr_masked_24 = dst_addr & 0xFFFFFF00; // */24
      if (src_addr_masked_22 == 0x4E1F0800 || /* 78.31.8.0/22 */
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
